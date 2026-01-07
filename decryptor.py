import os
import sys
import json
import hashlib
import re
import tarfile
import tempfile
import shutil
import uuid
import html
from datetime import datetime, timezone
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def get_openssl_derived_bytes(password, salt):
    """Mimics OpenSSL's EVP_BytesToKey for AES-128 and MD5."""
    password_bytes = password.encode('utf-8')
    # First hash provides the key (16 bytes)
    m1 = hashlib.md5(password_bytes + salt).digest()
    key = m1
    # Second hash provides the IV (16 bytes)
    m2 = hashlib.md5(m1 + password_bytes + salt).digest()
    iv = m2
    return key, iv

def generate_jex(notes_data, jex_path):
    """Generates a Joplin Export (JEX) file from the note list."""
    temp_dir = tempfile.mkdtemp()
    try:
        # Create Notebook Metadata
        nb_id = uuid.uuid4().hex
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        nb_content = f"ColorNote Import\n\n\nid: {nb_id}\ncreated_time: {now}\nupdated_time: {now}\nuser_created_time: {now}\nuser_updated_time: {now}\ntype_: 2"
        
        with open(os.path.join(temp_dir, f"{nb_id}.md"), 'w', encoding='utf-8') as f:
            f.write(nb_content)

        # Create Note Files
        for note in notes_data:
            title = html.unescape(note.get('title', ''))
            body = html.unescape(note.get('note', ''))
            if not title and not body: continue

            note_id = uuid.uuid4().hex
            # Convert Unix ms timestamps to ISO strings
            c_time = datetime.fromtimestamp(note.get('created_date', 0)/1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            m_time = datetime.fromtimestamp(note.get('modified_date', 0)/1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

            if note.get('type') == 16: # Checklist type
                # Convert ColorNote [V] and [ ] to Joplin/Markdown checkboxes
                body = body.replace("[ ]", "- [ ]")
                body = body.replace("[V]", "- [x]")

            deleted_time = note.get('modified_date', 0) if note.get('active_state') == 16 else 0
            
            md_content = f"{title}\n\n{body}\n\n\nid: {note_id}\nparent_id: {nb_id}\ncreated_time: {c_time}\nupdated_time: {m_time}\nuser_created_time: {c_time}\nuser_updated_time: {m_time}\nmarkup_language: 1\ntype_: 1\ndeleted_time: {deleted_time}"
            
            with open(os.path.join(temp_dir, f"{note_id}.md"), 'w', encoding='utf-8') as f:
                f.write(md_content)

        # Archive to JEX (tar format)
        with tarfile.open(jex_path, "w") as tar:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    tar.add(os.path.join(root, file), arcname=file)
    finally:
        shutil.rmtree(temp_dir)

def main():
    # 1. File Auto-Detection
    current_dir = os.path.dirname(os.path.abspath(__file__))
    extensions = ('.db', '.backup', '.dat')
    backup_files = [f for f in os.listdir(current_dir) if f.endswith(extensions)]

    if not backup_files:
        print(f"❌ No backup files found in: {current_dir}")
        input("Press Enter to exit...")
        return

    print("--- ColorNote Decryptor ---")
    input_file = backup_files[0]
    print(f"Target file: {input_file}")

    # 2. User Input
    password = input("\nEnter ColorNote password (default '0000'): ") or "0000"

    print("\nSelect Export Option:")
    print("1. JSON (Raw data)")
    print("2. JEX (Joplin Import Format)")
    print("3. Both")
    choice = input("Choice (1-3): ")

    # 3. Decryption Logic
    try:
        salt = "ColorNote Fixed Salt".encode('utf-8')
        key, iv = get_openssl_derived_bytes(password, salt)
        
        with open(input_file, 'rb') as f:
            file_bytes = f.read()
        
        # ColorNote backups usually have a 28-byte header
        offset = 28
        if len(file_bytes) <= offset:
            print("❌ Error: File is too small to contain encrypted data.")
            return

        encrypted_payload = file_bytes[offset:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Decrypt and decode, ignoring characters that can't be UTF-8 (like garbage blocks)
        decrypted_bytes = cipher.decrypt(encrypted_payload)
        decrypted_text = decrypted_bytes.decode('utf-8', errors='ignore')

        # Use regex to find potential JSON boundaries
        placeholder = "---JSON-RECORD-SEPARATOR---"
        cleaned_text = re.sub(r'\x00\x00..', placeholder, decrypted_text, flags=re.DOTALL)
        records = cleaned_text.split(placeholder)

        cleaned_objects = []
        for record in records:
            record = record.strip()
            first_brace = record.find('{')
            last_brace = record.rfind('}')
            
            if first_brace != -1 and last_brace > first_brace:
                json_str = record[first_brace:last_brace + 1]
                try:
                    # Individual block validation
                    parsed_json = json.loads(json_str)
                    cleaned_objects.append(parsed_json)
                except json.JSONDecodeError:
                    # Skips corrupted/garbage blocks (common in the first 16 bytes)
                    continue

        if not cleaned_objects:
            print("❌ Error: Could not extract any valid notes. Check your password.")
            input("\nPress Enter to close...")
            return

        # 4. Save Outputs
        base_name = os.path.splitext(input_file)[0]
        
        if choice in ['1', '3']:
            out_json = f"{base_name}_decrypted.json"
            with open(out_json, 'w', encoding='utf-8') as f:
                json.dump(cleaned_objects, f, indent=4, ensure_ascii=False)
            print(f"✅ JSON exported to: {out_json}")

        if choice in ['2', '3']:
            out_jex = f"{base_name}_export.jex"
            generate_jex(cleaned_objects, out_jex)
            print(f"✅ JEX exported to: {out_jex}")

    except Exception as e:
        print(f"❌ Critical Error: {e}")
    
    print("\nProcess finished.")
    input("Press Enter to close...")

if __name__ == "__main__":
    main()
