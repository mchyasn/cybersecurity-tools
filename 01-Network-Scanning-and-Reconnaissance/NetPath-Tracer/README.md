# NetPath-Tracer

## Description
NetPath-Tracer is a professional-grade network path mapper that performs multi-target traceroutes and saves hop-level data in JSON format. It is designed for red teamers, defenders, and network analysts who need to quickly map reachability, diagnose routing issues, or prepare internal path visualizations. The tool supports cross-platform execution (Linux/macOS/Windows) and includes robust error handling, structured output, and logging for each session.

## Features
- Multi-target traceroute execution
- Cross-platform support (Linux/macOS with `traceroute`, Windows with `tracert`)
- Hop-by-hop IP parsing from raw traceroute output
- Saves output to `scans/` and logs to `logs/`
- Timestamped session logs for traceability

## Installation
```bash
# Clone the repository
git clone https://github.com/your-org/NetPath-Tracer.git
cd NetPath-Tracer
```

No third-party dependencies are required. The script uses only Python's built-in modules.

## Usage
```bash
# Run traceroute on a single target
python3 main.py -t scanme.nmap.org

# Run traceroute on multiple targets and save output
python3 main.py -t google.com cloudflare.com github.com -o scans/multi_target_trace.json

# Trigger failure scenario and check logs
python3 main.py -t invalid.domain.fake -o scans/bad_trace.json
```

## Project Steps Performed

### Phase 1: Folder Structure Setup

### Phase 2: Script Development
- Used `argparse` for argument parsing
- Used `platform.system()` to detect OS
- Used `subprocess` to call system traceroute/tracert
- Parsed traceroute output line-by-line to extract hop IPs
- Exported hop data using `json.dump()` to `scans/`
- Created full session logs using `logging` module into `logs/`

### Phase 3: Testing Commands
```bash
# Test 1: Single domain
python3 main.py -t scanme.nmap.org

# Test 2: Multiple domains
python3 main.py -t google.com cloudflare.com github.com -o scans/multi_target_trace.json

# Test 3: Invalid input to trigger error handling
python3 main.py -t invalid.domain.fake -o scans/bad_trace.json
```

- Output JSON verified in `scans/`
- Error and info logs verified in `logs/`
- All tests passed

### Phase 4: Screenshots Taken
![Network Path Tracer](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/01-Network-Scanning-and-Reconnaissance/NetPath-Tracer/screenshots/0.png)
![Network Path Tracer](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/01-Network-Scanning-and-Reconnaissance/NetPath-Tracer/screenshots/1.png)
![Network Path Tracer](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/01-Network-Scanning-and-Reconnaissance/NetPath-Tracer/screenshots/2.png)
