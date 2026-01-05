import os
import glob
import getpass
import json
import zlib
from datetime import datetime

# Set environment variable before cryptography imports
os.environ["CRYPTOGRAPHY_OPENSSL_NO_LEGACY"] = "1"

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import padding
except ImportError:
    print("Error: 'cryptography' library not found. Run: pip install cryptography")
    exit()

# --- CONFIGURATION ---
SALT = b"ColorNote Fixed Salt"
ITERATIONS = 1
OFFSET = 28
# ---------------------

def openssl_kdf(password, salt, iterations):
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

def decode_stacked_json(raw_string):
    """
    Parses multiple concatenated JSON objects from a single string.
    Robust against braces {} appearing inside the note text.
    """
    decoder = json.JSONDecoder()
    pos = 0
    results = []
    
    # Strip any leading garbage/whitespace before the first '{'
    first_brace = raw_string.find('{')
    if first_brace != -1:
        pos = first_brace

    while pos < len(raw_string):
        try:
            # .raw_decode returns the object and the index where it ended
            obj, end_index = decoder.raw_decode(raw_string[pos:])
            results.append(obj)
            # Move position to the end of this object + skip potential whitespace
            pos += end_index
            
            # Fast-forward to next brace to skip any binary trash between objects
            rest = raw_string[pos:]
            next_brace = rest.find('{')
            if next_brace == -1:
                break
            pos += next_brace
            
        except json.JSONDecodeError:
            # If parsing fails, move forward one char and try again (brute force skip)
            pos += 1
            
    return results

def run_extraction():
    backup_files = glob.glob("*.backup")
    if not backup_files:
        print("Error: No .backup file found in the current folder.")
        return

    filename = backup_files[0]
    print(f"[*] Targeting file: {filename}")
    password = getpass.getpass("[?] Enter the master password: ")

    try:
        with open(filename, 'rb') as f:
            f.seek(OFFSET)
            encrypted_data = f.read()

        key, iv = openssl_kdf(password, SALT, ITERATIONS)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Robust Unpadding (PKCS7)
        unpadder = padding.PKCS7(128).unpadder()
        try:
            raw_decrypted = unpadder.update(padded_data) + unpadder.finalize()
        except ValueError:
            # Fallback if padding is malformed (rare but possible with wrong password)
            raw_decrypted = padded_data

        # Handle Zlib
        try:
            raw_decrypted = zlib.decompress(raw_decrypted)
        except zlib.error:
            pass

        decoded_content = raw_decrypted.decode('utf-8', errors='replace')
        
        # Use the new robust decoder instead of regex
        json_objects = decode_stacked_json(decoded_content)
        final_notes = []

        for data in json_objects:
            try:
                # Filter noise
                if "title" not in data and "note" not in data:
                    continue
                if data.get("title") == "syncable_settings":
                    continue

                # Extract content
                raw_note_val = data.get("note", "")
                note_body = raw_note_val
                
                # Handle double-nested JSON in 'note' field
                if isinstance(raw_note_val, str) and raw_note_val.strip().startswith('{'):
                    try:
                        nested = json.loads(raw_note_val)
                        if "D" in nested:
                            note_body = nested["D"]
                        # Checklists often look different; sometimes we want the whole object
                        elif isinstance(nested, dict):
                             note_body = str(nested) 
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
            except Exception:
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
