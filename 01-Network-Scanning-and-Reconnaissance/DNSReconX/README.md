# DNSReconX – Advanced DNS Recon Toolkit

## Description

DNSReconX is a robust DNS reconnaissance and enumeration toolkit designed for red teamers, defenders, and OSINT analysts. It combines asynchronous DNS record collection, brute-forcing, AXFR testing, and wildcard detection in a modular pipeline. Output is saved in JSON under `scans/`, and debug info is logged to `logs/`.

## Features

- Asynchronous resolution of A, AAAA, MX, NS, TXT, and CNAME records
- Brute-force subdomain discovery with wildcard DNS detection
- AXFR zone transfer attempts across all NS entries
- Custom wordlist support
- JSON result output with timestamped structure
- Built-in logging to `logs/debug.log`
- No external config dependencies required (but `configs/` folder present for expansion)

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/DNSReconX.git
cd DNSReconX

# Install Python dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Basic record enumeration
python3 main.py -d scanme.nmap.org

# Brute-force subdomains using default wordlist
python3 main.py -d scanme.nmap.org --brute

# Brute-force subdomains using custom wordlist
python3 main.py -d scanme.nmap.org --brute --wordlist configs/dns_wordlist.txt

# AXFR attempt with wildcard detection
python3 main.py -d scanme.nmap.org --axfr --wildcard
```

## Project Structure and Steps

### Phase 1: Folder Structure Setup

```bash
mkdir -p DNSReconX && cd DNSReconX
touch main.py README.md
mkdir -p scans logs screenshots docs configs
```

### Phase 2: Manual Initialization

- `configs/dns_wordlist.txt` added with starter DNS wordlist
- `docs/README.md` added with high-level module documentation

### Phase 3: Script Development

- `main.py` created with:
  - argparse support
  - async record enumeration via `aiodns`
  - brute-force subdomain logic
  - AXFR attempt across NS records
  - wildcard DNS detection using NXDOMAIN probes
  - logging to `logs/debug.log`
  - JSON output to `scans/{domain}_results.json`

### Phase 4: Testing Performed

```bash
# 1. Basic DNS record scan
python3 main.py -d scanme.nmap.org

# 2. Brute-force using internal wordlist
python3 main.py -d scanme.nmap.org --brute

# 3. AXFR and wildcard test
python3 main.py -d scanme.nmap.org --axfr --wildcard

# 4. Invalid domain test
python3 main.py -d nonexist.reconx.test
```
![DNS Reconnaissance Tool](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/01-Network-Scanning-and-Reconnaissance/DNSReconX/screenshots/0.png)
![DNS Reconnaissance Tool](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/01-Network-Scanning-and-Reconnaissance/DNSReconX/screenshots/00.png)
![DNS Reconnaissance Tool](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/01-Network-Scanning-and-Reconnaissance/DNSReconX/screenshots/000.png)

## License

MIT

## Author

mchyasn
