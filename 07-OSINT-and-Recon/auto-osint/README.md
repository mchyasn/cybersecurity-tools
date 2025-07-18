# auto-osint

## Description

auto-osint is a lightweight command-line tool for performing basic OSINT (Open Source Intelligence) collection on domains, IPs, and emails. It automates common recon tasks and stores results in organized logs for further analysis.

## Features

- WHOIS lookup  
- DNS resolution (A, MX, NS)  
- Subdomain enumeration via crt.sh  
- Email breach check (simulated)  
- IP reputation check (simulated)  
- Logs results to `/logs` with timestamps  

## Folder Structure

```
auto-osint/
├── auto_osint.py             -- Main script
├── logs/                     -- Scan result logs
├── scans/                    -- Manual recon scans
│   └── manual_scans.txt
├── req/                      -- Requirements & setup
│   ├── requirements.txt
│   └── install_notes.txt
├── screenshots/              -- Screenshots of tool in action
├── findings.md               -- Sample output findings
```

## Usage

Run OSINT scan:

```bash
python3 auto_osint.py -t <target>
```

### Examples

```bash
python3 auto_osint.py -t netflix.com
python3 auto_osint.py -t 45.33.32.156
python3 auto_osint.py -t test@example.com
```

## Requirements

**System:**
- Linux (Kali or Ubuntu recommended)
- whois
- curl or wget

**Python:**
- Python 3.x
- requests (`pip install -r req/requirements.txt`)

## Screenshots

`screenshots/`  
- `1_tool_overview.png` — OSINT run on domain
![Screenshot](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/07-OSINT-and-Recon/auto-osint/screenshots/tool.png)
- `2_email_breach_check.png` — Email test
![Screenshot](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/07-OSINT-and-Recon/auto-osint/screenshots/ip.png)
- `3_ip_reputation_check.png` — IP flag test
![Screenshot](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/07-OSINT-and-Recon/auto-osint/screenshots/email.png)

## Findings

Check `findings.md` for test results and tool behavior on various inputs.

## Disclaimer

This tool is for educational and ethical research use only.  
Do not scan domains, IPs, or emails you do not have permission to test.

## Author

Created and maintained by: [github.com/mchyasn](https://github.com/mchyasn)  
Part of my Cybersecurity Tools Portfolio

