# auto-hash — File Hashing Automation Tool

`auto-hash` is a lightweight command-line tool written in Python that recursively hashes all files in a given folder using common cryptographic algorithms (MD5, SHA1, SHA256). It is designed for cybersecurity analysts, malware researchers, and forensic investigators who need fast, automated file fingerprinting.

## Features

- Recursively scans a directory or a single file
- Computes MD5, SHA1, and SHA256 hashes
- Logs results to a timestamped output file
- Clean CLI interface with argument flags
- Ideal for malware analysis, triage, and integrity checking

## Project Structure
```
auto-hash/
├── auto_hash.py # Main Python script
├── requirements.txt # Empty (built-in modules only)
├── samples/ # Files to test hashing on
├── logs/ # Output hash logs
├── screenshots/ # Screenshots of CLI usage
└── README.md
```




## Usage

### 1. Clone the repository

```
git clone https://github.com/mchyasn/auto-hash.git
cd auto-hash
```

### 2. Add sample files to hash

```
echo "hello" > samples/test1.txt
echo "hash this" > samples/test2.txt
```

### 3. Run the tool

```
python3 auto_hash.py -t samples/ -o logs/hash_results.log
```

### 4. View the results

```
cat logs/hash_results.log
```

### Example Output

```yaml
# Auto-Hash Scan - 2025-07-13 14:00:22

samples/test1.txt
  MD5: 5d41402abc4b2a76b9719d911017c592
  SHA1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
  SHA256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
```

## Requirements
```
Python 3.x

Works on Linux (Kali, Ubuntu), macOS, and WSL

No external dependencies required
```
## Screenshots

![Auto-Hash Tool](https://raw.githubusercontent.com/mchyasn/auto-hash/main/screenshots/0.png)

## Learning Goals
```
Understand file hashing and integrity verification  
Automate repetitive tasks using Python scripting  
Practice secure file handling and logging in security workflows
```
## Disclaimer

This tool is intended for educational and ethical use only. Do not use it on systems or files without proper authorization.

## Author

Created and maintained by mchyasn

## Screenshots
![Screenshot](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/05-Digital-Forensics-and-Incident-Response/auto-hash/screenshots/0.png)
