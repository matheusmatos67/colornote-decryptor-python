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

# --- Dependency Check ---
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except ImportError:
    print("❌ Error: 'pycryptodome' library is missing.")
    print("Run: pip install pycryptodome")
    sys.exit(1)


# --- Constants ---
FIXED_SALT = "ColorNote Fixed Salt".encode('utf-8')
HEADER_OFFSET = 28


class ColorNoteCrypto:
    """Responsible solely for cryptographic operations (Key derivation & Decryption)."""

    def __init__(self, password: str = "0000"):
        self.password = password

    def _derive_key_iv(self) -> Tuple[bytes, bytes]:
        """Derives AES key and IV using OpenSSL-compatible MD5 hashing."""
        password_bytes = self.password.encode('utf-8')
        m1 = hashlib.md5(password_bytes + FIXED_SALT).digest()
        key = m1
        m2 = hashlib.md5(m1 + password_bytes + FIXED_SALT).digest()
        iv = m2
        return key, iv

    def decrypt(self, encrypted_data: bytes) -> str:
        """
        Decrypts raw bytes and returns the UTF-8 string.
        Raises ValueError if decryption fails.
        """
        if len(encrypted_data) < 44:
            raise ValueError("Data is too small to be a valid ColorNote payload.")

        # Skip the header
        payload = encrypted_data[HEADER_OFFSET:]
        
        key, iv = self._derive_key_iv()
        cipher = AES.new(key, AES.MODE_CBC, iv)

        try:
            decrypted_bytes = cipher.decrypt(payload)
            unpadded_bytes = unpad(decrypted_bytes, AES.block_size)
            # Decode with ignore to handle any binary garbage at the edges
            return unpadded_bytes.decode('utf-8', errors='ignore')
        except (ValueError, KeyError) as e:
            raise ValueError("Decryption failed. Incorrect password or corrupted file.") from e


class BackupParser:
    """Responsible for extracting valid JSON records from the raw decrypted stream."""

    @staticmethod
    def extract_notes(raw_text: str) -> List[Dict]:
        """
        Parses the decrypted stream using a bracket-balancing state machine.
        """
        notes = []
        length = len(raw_text)
        i = 0

        print(f"   🔍 Scanning {length} bytes of decrypted data...")

        while i < length:
            start_index = raw_text.find('{', i)
            if start_index == -1:
                break

            balance = 0
            in_quote = False
            escape = False
            end_index = -1

            for j in range(start_index, length):
                char = raw_text[j]

                if escape:
                    escape = False
                    continue
                if char == '\\':
                    escape = True
                    continue
                if char == '"':
                    in_quote = not in_quote
                    continue

                if not in_quote:
                    if char == '{':
                        balance += 1
                    elif char == '}':
                        balance -= 1
                        if balance == 0:
                            end_index = j
                            break
            
            if end_index != -1:
                candidate = raw_text[start_index : end_index + 1]
                try:
                    obj = json.loads(candidate)
                    if isinstance(obj, dict):
                        # Enhance with readable date
                        if 'modified_date' in obj:
                            obj['_readable_date'] = TimeUtils.fmt_time(obj['modified_date'])
                        notes.append(obj)
                    i = end_index + 1
                    continue 
                except json.JSONDecodeError:
                    i = start_index + 1
            else:
                i = start_index + 1
        
        return notes


class TimeUtils:
    """Helper for time formatting."""
    
    @staticmethod
    def fmt_time(ms_timestamp: Optional[int]) -> str:
        if not ms_timestamp:
            return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        return datetime.fromtimestamp(ms_timestamp / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class JoplinExporter:
    """Responsible for converting notes into a Joplin Export Archive (.jex)."""

    def __init__(self, notes: List[Dict]):
        self.notes = notes

    def export(self, output_path: str):
        if not self.notes:
            print("⚠️ No notes to export.")
            return

        temp_dir = tempfile.mkdtemp()
        try:
            nb_id = uuid.uuid4().hex
            self._create_notebook_meta(temp_dir, nb_id)
            
            count = 0
            for note in self.notes:
                # 0=Note, 16=Checklist
                if note.get('type') in [0, 16]:
                    self._create_note_file(note, temp_dir, nb_id)
                    count += 1
            
            print(f"   ℹ️  Packaged {count} notes into JEX (filtered {len(self.notes)-count} non-note items).")
            self._create_tar(temp_dir, output_path)
            
        finally:
            shutil.rmtree(temp_dir)

    def _create_notebook_meta(self, temp_dir: str, nb_id: str):
        now = TimeUtils.fmt_time(None)
        content = (
            f"ColorNote Import\n\n\nid: {nb_id}\n"
            f"created_time: {now}\nupdated_time: {now}\n"
            f"user_created_time: {now}\nuser_updated_time: {now}\ntype_: 2"
        )
        with open(os.path.join(temp_dir, f"{nb_id}.md"), 'w', encoding='utf-8') as f:
            f.write(content)

    def _create_note_file(self, note: Dict, temp_dir: str, nb_id: str):
        title = html.unescape(note.get('title', '') or "Untitled")
        body = html.unescape(note.get('note', '') or "")
        
        c_time = TimeUtils.fmt_time(note.get('created_date'))
        m_time = TimeUtils.fmt_time(note.get('modified_date'))

        # Convert Checklists
        if note.get('type') == 16:
            body = body.replace("[ ]", "- [ ] ").replace("[V]", "- [x] ")

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

        safe_filename = "".join([c for c in note_id if c.isalnum() or c in ('-','_')])
        with open(os.path.join(temp_dir, f"{safe_filename}.md"), 'w', encoding='utf-8') as f:
            f.write(md_content)

    def _create_tar(self, source_dir: str, output_path: str):
        with tarfile.open(output_path, "w") as tar:
            for root, _, files in os.walk(source_dir):
                for file in files:
                    tar.add(os.path.join(root, file), arcname=file)


# --- CLI Utilities ---

def select_file() -> str:
    """Interactive file selection."""
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
    parser = argparse.ArgumentParser(description="Decrypt ColorNote backups (Refactored).")
    parser.add_argument("file", nargs="?", help="Path to the .backup/.db file")
    parser.add_argument("-p", "--password", help="Backup password")
    parser.add_argument("-f", "--format", choices=['json', 'jex', 'both'], default='both', help="Output format")
    args = parser.parse_args()

    # 1. Inputs
    target_file = args.file if args.file else select_file()
    password = args.password
    if not password:
        use_default = input("Use default password '0000'? (Y/n): ").lower() != 'n'
        password = "0000" if use_default else getpass.getpass("Enter Password: ")

    print(f"\n🔐 Processing: {target_file}...")

    # 2. Read File
    try:
        with open(target_file, 'rb') as f:
            encrypted_data = f.read()
    except FileNotFoundError:
        print(f"❌ Error: File not found {target_file}")
        sys.exit(1)

    # 3. Decrypt
    crypto = ColorNoteCrypto(password)
    try:
        decrypted_text = crypto.decrypt(encrypted_data)
        print("✅ Decryption successful.")
    except ValueError as e:
        print(f"\n❌ {e}")
        sys.exit(1)

    # 4. Parse
    notes = BackupParser.extract_notes(decrypted_text)
    print(f"📊 Total records found: {len(notes)}")

    if not notes:
        print("⚠️ Warning: File decrypted but no records found.")
        sys.exit(0)

    # 5. Export
    base_name = os.path.splitext(target_file)[0]

    if args.format in ['json', 'both']:
        out_json = f"{base_name}_decrypted.json"
        with open(out_json, 'w', encoding='utf-8') as f:
            json.dump(notes, f, indent=4, ensure_ascii=False)
        print(f"💾 JSON Saved: {out_json}")

    if args.format in ['jex', 'both']:
        out_jex = f"{base_name}_export.jex"
        exporter = JoplinExporter(notes)
        exporter.export(out_jex)
        print(f"💾 JEX Saved:  {out_jex}")

    print("\n✨ Done.")

if __name__ == "__main__":
    main()
