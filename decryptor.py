import os
import sys
import json
import hashlib
import tarfile
import tempfile
import shutil
import uuid
import html
import argparse
import getpass
from datetime import datetime, timezone
from typing import List, Dict, Tuple, Optional

# Dependency check
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except ImportError:
    print("❌ Error: 'pycryptodome' library is missing.")
    print("Run: pip install pycryptodome")
    sys.exit(1)

class ColorNoteDecryptor:
    FIXED_SALT = "ColorNote Fixed Salt".encode('utf-8')

    def __init__(self, filepath: str, password: str = "0000"):
        self.filepath = filepath
        self.password = password
        self.raw_data = b""
        self.decrypted_text = ""
        self.notes: List[Dict] = []

    def _derive_key_iv(self) -> Tuple[bytes, bytes]:
        """Derives AES key and IV using OpenSSL-compatible MD5 hashing."""
        password_bytes = self.password.encode('utf-8')
        m1 = hashlib.md5(password_bytes + self.FIXED_SALT).digest()
        key = m1
        m2 = hashlib.md5(m1 + password_bytes + self.FIXED_SALT).digest()
        iv = m2
        return key, iv

    def decrypt(self) -> bool:
        """Decrypts the AES-128-CBC stream."""
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"File not found: {self.filepath}")

        with open(self.filepath, 'rb') as f:
            self.raw_data = f.read()

        if len(self.raw_data) < 44:
            raise ValueError("File is too small to be a valid ColorNote backup.")

        # ColorNote has a 28-byte header before the encrypted payload
        offset = 28
        encrypted_payload = self.raw_data[offset:]
        
        key, iv = self._derive_key_iv()
        cipher = AES.new(key, AES.MODE_CBC, iv)

        try:
            decrypted_bytes = cipher.decrypt(encrypted_payload)
            # PKCS7 unpadding verifies the password implicitly
            unpadded_bytes = unpad(decrypted_bytes, AES.block_size)
            # Decode with 'ignore' to strip binary wrappers/Java serialization headers
            self.decrypted_text = unpadded_bytes.decode('utf-8', errors='ignore') 
            return True
        except (ValueError, KeyError):
            return False

    def extract_json_smart(self):
        """
        Parses the decrypted stream using a bracket-balancing state machine.
        This ignores garbage between records and handles nested JSON correctly.
        """
        self.notes = []
        text = self.decrypted_text
        length = len(text)
        i = 0

        print(f"   🔍 Scanning {length} bytes of decrypted data...")

        while i < length:
            # Find the start of a potential JSON object
            start_index = text.find('{', i)
            if start_index == -1:
                break

            # State machine to find the matching closing brace
            balance = 0
            in_quote = False
            escape = False
            end_index = -1

            for j in range(start_index, length):
                char = text[j]

                # Handle escape sequences (e.g. \" inside a string)
                if escape:
                    escape = False
                    continue
                if char == '\\':
                    escape = True
                    continue

                # Handle Quotes: Don't count brackets inside strings
                if char == '"':
                    in_quote = not in_quote
                    continue

                if not in_quote:
                    if char == '{':
                        balance += 1
                    elif char == '}':
                        balance -= 1
                        # If balance hits zero, we found the closing brace
                        if balance == 0:
                            end_index = j
                            break
            
            if end_index != -1:
                # Extract candidate string
                candidate = text[start_index : end_index + 1]
                try:
                    # Parse JSON to verify validity
                    obj = json.loads(candidate)
                    if isinstance(obj, dict):
                        # Add metadata for easier manual debugging
                        if 'modified_date' in obj:
                            obj['_readable_date'] = self._fmt_time(obj['modified_date'])
                        self.notes.append(obj)
                    
                    # Success! Move index past this object
                    i = end_index + 1
                    continue 
                except json.JSONDecodeError:
                    # False positive: bracket balanced, but invalid JSON content.
                    # Advance just past the opening brace and try again
                    i = start_index + 1
            else:
                # Unbalanced brackets (broken file or end of stream)
                i = start_index + 1

    def export_jex(self, output_path: str):
        """Creates a Joplin Export (JEX) archive."""
        if not self.notes:
            print("⚠️ No notes to export.")
            return

        temp_dir = tempfile.mkdtemp()
        try:
            nb_id = uuid.uuid4().hex
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            
            # 1. Create Notebook Metadata (The folder in Joplin)
            nb_content = (
                f"ColorNote Import\n\n\nid: {nb_id}\n"
                f"created_time: {now}\nupdated_time: {now}\n"
                f"user_created_time: {now}\nuser_updated_time: {now}\ntype_: 2"
            )
            with open(os.path.join(temp_dir, f"{nb_id}.md"), 'w', encoding='utf-8') as f:
                f.write(nb_content)

            # 2. Create Note Files
            count = 0
            for note in self.notes:
                # Filter: Only export Notes (0) and Checklists (16)
                # Skip Folders (128) and Settings (256)
                if note.get('type') in [0, 16]:
                    self._create_joplin_note(note, temp_dir, nb_id)
                    count += 1
            
            print(f"   ℹ️  Packaged {count} notes into JEX (filtered {len(self.notes)-count} non-note items).")

            # 3. Tar it up
            with tarfile.open(output_path, "w") as tar:
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        tar.add(os.path.join(root, file), arcname=file)
        finally:
            shutil.rmtree(temp_dir)

    def _create_joplin_note(self, note: Dict, temp_dir: str, nb_id: str):
        title = html.unescape(note.get('title', '') or "Untitled")
        body = html.unescape(note.get('note', '') or "")
        
        c_time = self._fmt_time(note.get('created_date'))
        m_time = self._fmt_time(note.get('modified_date'))

        # Convert ColorNote Checklists to Markdown
        if note.get('type') == 16:
            body = body.replace("[ ]", "- [ ] ").replace("[V]", "- [x] ")

        # Handle Deleted/Archived state
        is_deleted = note.get('active_state') == 16
        deleted_time = note.get('modified_date', 0) if is_deleted else 0

        note_id = uuid.uuid4().hex
        md_content = (
            f"{title}\n\n{body}\n\n\n"
            f"id: {note_id}\nparent_id: {nb_id}\n"
            f"created_time: {c_time}\nupdated_time: {m_time}\n"
            f"user_created_time: {c_time}\nuser_updated_time: {m_time}\n"
            f"markup_language: 1\ntype_: 1\ndeleted_time: {deleted_time}"
        )

        # Sanitize filename
        safe_filename = "".join([c for c in note_id if c.isalnum() or c in ('-','_')])
        with open(os.path.join(temp_dir, f"{safe_filename}.md"), 'w', encoding='utf-8') as f:
            f.write(md_content)

    @staticmethod
    def _fmt_time(ms_timestamp: Optional[int]) -> str:
        """Converts Unix MS timestamp to Joplin ISO format."""
        if not ms_timestamp:
            return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        return datetime.fromtimestamp(ms_timestamp/1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

def select_file() -> str:
    """Auto-detects backup files in the current folder."""
    current_dir = os.getcwd()
    exts = ('.db', '.backup', '.dat')
    files = [f for f in os.listdir(current_dir) if f.lower().endswith(exts)]

    if not files:
        print(f"❌ No backup files {exts} found in: {current_dir}")
        sys.exit(0)

    if len(files) == 1:
        print(f"📄 Found file: {files[0]}")
        return files[0]

    print("\nFound multiple backup files:")
    for idx, f in enumerate(files):
        print(f"{idx + 1}. {f}")
    
    while True:
        try:
            choice = int(input(f"Select file (1-{len(files)}): "))
            if 1 <= choice <= len(files):
                return files[choice - 1]
        except ValueError:
            pass
        print("Invalid selection.")

def main():
    parser = argparse.ArgumentParser(description="Decrypt ColorNote backups (Final Version).")
    parser.add_argument("file", nargs="?", help="Path to the .backup/.db file")
    parser.add_argument("-p", "--password", help="Backup password")
    parser.add_argument("-f", "--format", choices=['json', 'jex', 'both'], default='both', help="Output format")
    args = parser.parse_args()

    # 1. Select File
    target_file = args.file if args.file else select_file()

    # 2. Get Password
    password = args.password
    if not password:
        use_default = input("Use default password '0000'? (Y/n): ").lower() != 'n'
        password = "0000" if use_default else getpass.getpass("Enter Password: ")

    print(f"\n🔐 Processing: {target_file}...")
    
    decryptor = ColorNoteDecryptor(target_file, password)
    
    try:
        # 3. Decrypt
        if not decryptor.decrypt():
            print("\n❌ Decryption failed! Password incorrect.")
            sys.exit(1)
        
        print("✅ Decryption successful.")
        
        # 4. Parse
        decryptor.extract_json_smart()
        
        total_found = len(decryptor.notes)
        print(f"📊 Total records found: {total_found}")

        if total_found == 0:
            print("⚠️ Warning: File decrypted but no records found. It might be empty.")
            sys.exit(0)

    except Exception as e:
        print(f"\n❌ Critical Error: {e}")
        sys.exit(1)

    # 5. Export
    base_name = os.path.splitext(target_file)[0]

    if args.format in ['json', 'both']:
        out_json = f"{base_name}_decrypted.json"
        with open(out_json, 'w', encoding='utf-8') as f:
            json.dump(decryptor.notes, f, indent=4, ensure_ascii=False)
        print(f"💾 JSON Saved: {out_json} (Full Backup)")

    if args.format in ['jex', 'both']:
        out_jex = f"{base_name}_export.jex"
        decryptor.export_jex(out_jex)
        print(f"💾 JEX Saved:  {out_jex} (Ready for Joplin Import)")

    print("\n✨ Done.")

if __name__ == "__main__":
    main()
