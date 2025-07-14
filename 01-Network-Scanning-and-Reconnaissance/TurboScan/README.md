# TurboScan

## Description

TurboScan is a high‑performance asynchronous network scanner that rapidly discovers live hosts, open ports and service banners across large IP ranges (e.g., /16). It supports single hosts, IP lists and CIDR subnets, providing intelligent concurrency control, connection time‑outs and structured JSON output. TurboScan is ideal for red, blue and reconnaissance teams who need fast enumeration without the overhead of a full Nmap run.

## Features

* Asynchronous scanning using Python `asyncio`
* Custom IP‑range expansion (CIDR and IP‑list support)
* Fast TCP connection attempts with per‑port time‑out control
* Optional banner grabbing for identified ports
* Results saved as JSON to `scans/`
* Debug logging written to `logs/debug.log`

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/TurboScan.git
cd TurboScan

# Install requirements (if any are added later)
pip install -r requirements.txt
```

## Usage

```bash
# Scan specific ports on a single host
python3 main.py -t scanme.nmap.org -p 22,80,443 -o scans/single_target.json

# Scan a CIDR subnet (/30 = 4 IPs)
python3 main.py -t 192.168.1.0/30 -p 80,443 -o scans/subnet_test.json

# Scan multiple IPs or domains separated by comma
python3 main.py -t scanme.nmap.org,google.com -p 80 -o scans/multi_target.json

# Scan and grab banners
python3 main.py -t scanme.nmap.org -p 22 -b -o scans/banner_grab.json
```

## Project Steps Performed

### Phase 1: Folder Structure Setup

```bash
mkdir -p TurboScan && cd TurboScan
touch main.py README.md
mkdir -p scans logs screenshots
```

### Phase 2: Script Development

* Used `argparse` for command‑line parsing.
* Implemented high‑speed scanning with `asyncio.open_connection`.
* Added IP/CIDR/hostname expansion with the `ipaddress` module.
* Implemented banner grabbing via the `-b` flag.
* Handled time‑outs and socket errors gracefully.
* Saved scan results to `scans/` as JSON.
* Implemented logging to `logs/debug.log`.

### Phase 3: Testing Commands

```bash
# Test 1: Single host, known ports
python3 main.py -t scanme.nmap.org -p 22,80 -o scans/single_target.json

# Test 2: CIDR scan
python3 main.py -t 192.168.1.0/30 -p 80 -o scans/subnet_test.json

# Test 3: Invalid host to trigger failure
python3 main.py -t fake.invalid -p 80 -o scans/invalid.json

# Test 4: Banner grabbing
python3 main.py -t scanme.nmap.org -p 22 -b -o scans/banner_grab.json
```
![Turbo Network Scanner](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/01-Network-Scanning-and-Reconnaissance/TurboScan/screenshots/0.png)
```
* All outputs saved in `scans/`.
* Logging verified in `logs/debug.log` (empty if no warnings/errors).
* All tests passed successfully.
```
## License

MIT

## Author

mchyasn
