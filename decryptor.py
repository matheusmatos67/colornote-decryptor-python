import os
import glob
import getpass
import json
import zlib
import re
from datetime import datetime

# Set environment variable before cryptography imports
os.environ["CRYPTOGRAPHY_OPENSSL_NO_LEGACY"] = "1"

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("Error: 'cryptography' library not found. Run: pip install cryptography")
    exit()

def openssl_kdf(password, salt, iterations=1):
    d = hashes.Hash(hashes.MD5(), backend=default_backend())
    d.update(password.encode('utf-8'))
    d.update(salt)
    result = d.finalize()
    for _ in range(1, iterations):
        d = hashes.Hash(hashes.MD5(), backend=default_backend())
        d.update(result)
        result = d.finalize()
    return result[:16], result[:16]

def format_date(ms_timestamp):
    if not ms_timestamp or ms_timestamp == 0:
        return None
    return datetime.fromtimestamp(ms_timestamp / 1000.0).strftime('%Y-%m-%d %H:%M:%S')

def run_extraction():
    backup_files = glob.glob("*.backup")
    if not backup_files:
        print("Error: No .backup file found in the current folder.")
        return

    filename = backup_files[0]
    print(f"[*] Targeting file: {filename}")
    password = getpass.getpass("[?] Enter the master password: ")

    iterations = 1 
    offset = 28
    salt = "ColorNote Fixed Salt".encode('utf-8')

    try:
        with open(filename, 'rb') as f:
            f.seek(offset)
            encrypted_data = f.read()

        key, iv = openssl_kdf(password, salt, iterations)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        raw_decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
        
        padding_len = raw_decrypted[-1]
        if 0 < padding_len <= 16:
            raw_decrypted = raw_decrypted[:-padding_len]

        try:
            raw_decrypted = zlib.decompress(raw_decrypted)
        except zlib.error:
            pass

        decoded_content = raw_decrypted.decode('utf-8', errors='replace')
        json_blocks = re.findall(r'\{.*?\}', decoded_content)
        final_notes = []

        for block in json_blocks:
            try:
                data = json.loads(block)
                if "title" not in data and "note" not in data:
                    continue
                if data.get("title") == "syncable_settings":
                    continue

                raw_note_val = data.get("note", "")
                note_body = raw_note_val
                if isinstance(raw_note_val, str) and raw_note_val.startswith('{'):
                    try:
                        nested = json.loads(raw_note_val)
                        note_body = nested.get("D", raw_note_val)
                    except:
                        pass

                clean_entry = {
                    "id": data.get("_id"),
                    "title": data.get("title", "Untitled"),
                    "content": note_body,
                    "type": "checklist" if data.get("type") == 1 else "text",
                    "created": format_date(data.get("created_date")),
                    "modified": format_date(data.get("modified_date")),
                    "folder_id": data.get("folder_id"),
                    "color_index": data.get("color_index")
                }
                final_notes.append(clean_entry)
            except:
                continue

        output_json = filename.replace(".backup", "_extracted.json")
        with open(output_json, 'w', encoding='utf-8') as f_out:
            json.dump(final_notes, f_out, indent=4, ensure_ascii=False)

        print(f"\n--- SUCCESS ---")
        print(f"[*] Decrypted and parsed {len(final_notes)} notes.")
        print(f"[*] Result saved to: {output_json}")

    except Exception as e:
        print(f"\n[!] Critical Error: {e}")

if __name__ == "__main__":
    run_extraction()
