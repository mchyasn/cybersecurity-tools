# Async Port & Banner Scanner

## Description
A fast asynchronous TCP port scanner with banner grabbing, written in Python using `asyncio`. Designed to identify open ports and fingerprint services on a given host. Supports port lists and ranges, outputs structured JSON, and logs events for debugging. Ideal for red team reconnaissance and blue team asset auditing.

## Features
- Asynchronous TCP scanning using Python asyncio
- Banner grabbing for services like HTTP, SSH, and FTP
- Support for single, comma-separated, or ranged ports
- Structured output saved to `scans/`
- Logging to `logs/scan.log`
- Graceful error handling for timeouts, invalid hosts, and connection failures

## Installation

```bash
# Clone the repository and navigate into the tool directory
git clone https://github.com/your-org/Async-Port-Banner-Scanner.git
cd Async-Port-Banner-Scanner
```
# (Optional but recommended) Create a virtual environment
```
python3 -m venv venv
source venv/bin/activate
```
```
# Install required packages
pip install -r requirements.txt
```
```
# Scan specific ports
python3 main.py -t scanme.nmap.org -p 22,80,443 -o scans/common_ports.json

# Scan a port range
python3 main.py -t scanme.nmap.org -p 20-25 -o scans/range_test.json

# Scan a single port
python3 main.py -t scanme.nmap.org -p 22 -o scans/single_port.json

# Invalid target test (logs handled error)
python3 main.py -t 256.256.256.256 -p 80 -o scans/invalid_target.json
```

# Closed/filtered port
python3 main.py -t scanme.nmap.org -p 9999 -o scans/closed_port.json

# Help menu
```
python3 main.py --help
```
```
Folder Structure
Async-Port-Banner-Scanner/
├── main.py                 # Main scanning script
├── README.md               # Project documentation
├── requirements.txt        # Dependencies
├── scans/                  # JSON output files
│   └── common_ports.json, range_test.json ...
├── logs/                   # Debug logs
│   └── scan.log
├── screenshots/            # Manual screenshots (not auto-generated)
└── configs/                # (Empty unless needed later)
```
License
MIT
