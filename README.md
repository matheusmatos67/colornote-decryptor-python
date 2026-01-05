# ColorNote Backup Decryptor (Python)

A streamlined Python utility to decrypt and extract notes from ColorNote `.backup` files into formatted JSON.

## 🚀 About this Project
This tool was "vibe-coded" with the assistance of **Gemini 3 flash (Google AI)** to port legacy decryption logic into a modern, easy-to-use Python script. 

### 🤝 Credits & Inspiration
This project is a Python implementation inspired by the original Java work done by **[olejorgenb](https://github.com/olejorgenb/ColorNote-backup-decryptor)**. We've simplified the process to handle modern Python environments and specific 1-iteration/28-offset requirements.

## 🛠️ Features
- **One-Step Extraction**: Decrypts, decompresses (Zlib), and cleans JSON in one go.
- **Auto-Detection**: Scans the folder for `.backup` files automatically.
- **Readable Dates**: Converts Unix timestamps to human-friendly formats.
- **Clean Output**: Unpacks nested note data into a standard JSON list.

## 📦 Installation
```bash
pip install cryptography
```

## 📖 Usage

1. Place your `.backup` file in the same directory as `decryptor.py`.
2. Run the script:
   ```bash
   python decryptor.py
