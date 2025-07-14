# SmartPortMap – Adaptive Port and Service Mapper

## Description
SmartPortMap is an adaptive port and service mapping tool designed to intelligently scan targets based on detected operating systems and port profiles. It optimizes scanning time and relevance by tailoring the probes according to host fingerprinting results and includes dynamic adjustment of scan strategies based on known OS behaviors.

## Features
- ICMP ping and TCP port scanning with `asyncio`
- Banner grabbing for responsive TCP services
- OS guessing via TTL + TCP window size heuristics (best-effort)
- Conditional scan rules (e.g., skip SMB on Linux-like targets)
- Modular scan strategy builder
- Structured output in JSON format
- Timestamped debug logging to `logs/debug.log`

## Installation

```bash
git clone https://github.com/your-org/SmartPortMap.git
cd SmartPortMap
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python3 main.py -t scanme.nmap.org -p 22,80,443

# Output results to scans folder
python3 main.py -t 192.168.1.1 -p 1-1024 -o scans/full_scan.json
```

## Project Steps Performed

### Phase 1: Folder Structure Setup

```bash
SmartPortMap/
├── main.py
├── requirements.txt
├── README.md
├── scans/               # Stores JSON results
├── logs/                # Stores debug.log
├── configs/             # Contains config.txt (placeholder content added)
│   └── config.txt       # "Placeholder config for future scan rules"
├── docs/                # Contains internal README.md
│   └── README.md        # "Placeholder documentation"
├── screenshots/         # For manual captures
```

### Phase 2: Script Development

- Developed core async TCP scanner using `asyncio` and `asyncio.open_connection`
- Implemented TTL-based OS guesser (very basic, best-effort)
- Banner grabbing for common ports: 21, 22, 23, 80, 443
- Scan profile rules:
  - If TTL suggests Linux/Unix → skip SMB, RDP
  - If TTL suggests Windows → include SMB, RDP
- Results auto-saved to `scans/`
- All activity and errors logged to `logs/debug.log`

### Phase 3: Testing Commands

```bash
# Scan multiple common ports
python3 main.py -t scanme.nmap.org -p 22,80,443

# Scan full range with output
python3 main.py -t 192.168.1.1 -p 1-1024 -o scans/office_host.json

# Trigger scan with unreachable target
python3 main.py -t 10.255.255.1 -p 80,443
```

### Phase 4: Screenshots Taken

- `screenshots/scan_output_success.png`
- `screenshots/debug_log_inspect.png`
- `screenshots/os_guess_linux.png`

## License
MIT

## Author
mchyasn
