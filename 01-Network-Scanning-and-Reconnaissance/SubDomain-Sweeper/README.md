# SubDomain-Sweeper

## Description
SubDomain-Sweeper is a high-speed asynchronous subdomain enumerator designed to resolve large wordlists against a given root domain. It leverages Python's `asyncio` and `socket.gethostbyname` to perform massive DNS resolution in parallel, with robust error handling and customizable concurrency. Ideal for red teamers and reconnaissance workflows where speed and accuracy matter.

## Features
- Asynchronous DNS resolution using `asyncio` and `socket.gethostbyname`
- Handles wordlists of any size
- Adjustable concurrency via command-line argument
- Structured output in JSON format (saved to `scans/`)
- Full error logging (saved to `logs/`)
- Graceful handling of timeouts and DNS failures

## Installation
```bash
# Clone the repository
git clone https://github.com/your-org/SubDomain-Sweeper.git
cd SubDomain-Sweeper
```

No external dependencies required beyond the standard library.

## Usage
```bash
# Run subdomain sweep
python3 main.py -d scanme.nmap.org -w configs/test_wordlist.txt -o scans/sweep_output.json

# Stress test with high concurrency
python3 main.py -d scanme.nmap.org -w configs/test_wordlist.txt -c 100 -o scans/high_concurrency.json

# Trigger invalid domain error
python3 main.py -d invalid.example.fake -w configs/test_wordlist.txt -o scans/invalid_domain.json
```

## Project Steps Performed

### Phase 1: Folder Structure Setup
```bash
mkdir -p SubDomain-Sweeper && cd SubDomain-Sweeper
touch main.py README.md
mkdir -p configs scans logs screenshots
```

### Phase 2: Script Development
- Used `argparse` to handle domain, wordlist, output file, and concurrency
- Used `asyncio` and `socket.gethostbyname` for concurrent DNS resolution
- Captured all results in structured JSON format saved to `scans/`
- Implemented full error logging to `logs/`
- Validated input files and displayed meaningful CLI output

### Phase 3: Testing Commands
```bash
# Test 1: Basic test
python3 main.py -d scanme.nmap.org -w configs/test_wordlist.txt -o scans/sweep_output.json

# Test 2: High concurrency
python3 main.py -d scanme.nmap.org -w configs/test_wordlist.txt -c 100 -o scans/high_concurrency.json

# Test 3: Invalid domain test
python3 main.py -d invalid.example.fake -w configs/test_wordlist.txt -o scans/invalid_domain.json

# Test 4: Missing file test
python3 main.py -d scanme.nmap.org -w configs/missing_file.txt -o scans/missing_wordlist.json
```
![Subdomain Enumeration Tool](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/01-Network-Scanning-and-Reconnaissance/SubDomain-Sweeper/screenshots/0.png)
```
- Output results saved in `scans/`
- Errors logged to `logs/errors.log`
- Script passed tests with various domains and concurrency settings
```

## Author: mchyasn


