# ColorNote Backup Decryptor & Exporter (Python)

A streamlined Python utility to decrypt ColorNote `.backup`, `.db`, and `.dat` files. It extracts notes into formatted JSON or **Joplin Export (JEX)** files for easy migration.

## 🚀 About this Project
This tool was "vibe-coded" with the assistance of **Gemini 3 (Google AI)** to port legacy decryption logic into a modern, easy-to-use Python script.

### 🤝 Credits & Inspiration
This project is a Python implementation inspired by the original Java work done by **[olejorgenb](https://github.com/olejorgenb/ColorNote-backup-decryptor)**. We've simplified the process to handle modern Python environments and added specific support for migrating data to the **Joplin** note-taking app.

## 🛠️ Features
- **Joplin Support (.jex)**: Generates a distinct import file for Joplin, preserving creation/modification dates.
- **Checklist Conversion**: Automatically converts ColorNote checklists (`[ ]`, `[V]`) into Markdown checkboxes (`- [ ]`, `- [x]`).
- **Robust Parsing**: Uses Regex and heuristic cleaning to handle corrupted blocks or binary garbage often found in older backups.
- **Auto-Detection**: Scans the folder for `.backup`, `.db`, and `.dat` files automatically.
- **Readable Dates**: Converts Unix timestamps to human-friendly ISO formats.

## 📦 Installation

This script uses `pycryptodome` for AES decryption.

```bash
pip install pycryptodome
```

## 📖 Usage

1. Place your backup file (e.g., `123456789.backup` or `colornote.db`) in the same directory as the script.
2. Run the script:
   ```bash
   python decryptor.py
   ```
3. Enter your Master Password (default is usually `0000` if you never set one).
4. Generates both JSON and JEX files.

  
### 📥 Importing into Joplin
If you chose the JEX option:
1. Open **Joplin**.
2. Go to **File** > **Import** > **Joplin Export File (JEX)**.
3. Select the generated `_export.jex` file.

## ⚠️ Disclaimer
This tool is provided "as is" for data recovery and migration purposes. Always keep a backup of your original files before running scripts against them.
