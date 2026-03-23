Gujigai
A lightweight, signature-based antivirus simulator written in C. 

Gujigai uses **SHA-256 Hashing**, **File Extension Analysis**, and **YARA Rules** to identify and neutralize potentially malicious files.

## Features
* **Hash Matching:** Compares file SHA-256 hashes against a built-in database of known malware.
* **Heuristic Extension Check:** Flags suspicious script extensions (.vbs, .bat, .ps1).
* **YARA Integration:** Scans file contents using industry-standard YARA rules.
* **Auto-Quarantine:** Automatically removes files flagged as malicious.

## Prerequisites
You must have `libssl` and `libyara` installed on your system.

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install libssl-dev libyara-dev build-essential



  Usage: gcc main.c -o filename -lcrypto -lyara
