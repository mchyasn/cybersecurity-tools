# auto-scan

`auto-scan` is a fast, CLI-based recon tool that wraps around Nmap to automate port scanning with presets. It helps analysts quickly scan for open services on target systems, using structured logs and clean command-line inputs.

## Features

- Supports `quick`, `stealth`, `full`, and `custom` scan modes
- Generates timestamped `.log` files under `logs/`
- Lightweight and requires only Nmap
- Designed for labs, CTFs, and recon workflows

## Scan Modes

| Mode     | Description                             |
|----------|-----------------------------------------|
| quick    | Fast top 100 ports with service version |
| stealth  | SYN scan, slower, evades detection      |
| full     | All ports (1–65535), slower             |
| custom   | User-defined port range                 |

## Usage

```bash
python3 auto_scan.py -t scanme.nmap.org --mode quick
python3 auto_scan.py -t scanme.nmap.org --mode stealth
python3 auto_scan.py -t scanme.nmap.org --mode custom -p 22,80,443
```
Output
Scans are saved in:
```
logs/scanme_nmap_org_quick_2025-07-13_14-35-15.log
```

## screenshots 

`quick scan`
![Auto-Scan Quick Results](https://raw.githubusercontent.com/mchyasn/auto-scan/main/screenshots/quick.png)

`full`
![Auto-Scan Quick Results](https://raw.githubusercontent.com/mchyasn/auto-scan/main/screenshots/full.png)

#### Author
##### Built by mchyasn
##### Part of the Cybersecurity Tools Portfolio series

## Screenshots
![Screenshot](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/01-Network-Scanning-and-Reconnaissance/auto-scan/screenshots/quick.png)
![Screenshot](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/01-Network-Scanning-and-Reconnaissance/auto-scan/screenshots/full.png)
