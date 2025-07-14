# TracerBatch – Batch Traceroute Aggregator

## Description
TracerBatch is a cross-platform batch traceroute aggregator that performs multi-target traceroutes, parses hop-by-hop routing paths, and exports the data in structured JSON format. It is ideal for red teamers, defenders, or analysts who need to visualize or analyze internal or external network paths at scale.

## Features
- Multi-target traceroute support
- Works on Linux/macOS (`traceroute`) and Windows (`tracert`)
- Hop-by-hop IP parsing from raw traceroute output
- Saves structured output to `scans/`
- Logs session activity to `logs/debug.log`
- Robust error handling and graceful failures

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/TracerBatch.git
cd TracerBatch

# No third-party dependencies are required.
# The tool uses only Python's standard library.
```

## Usage

```bash
# Run traceroute on a single target
python3 main.py -t scanme.nmap.org

# Run traceroute on multiple targets
python3 main.py -t google.com cloudflare.com github.com -o scans/multi_trace.json

# Trigger an error for testing
python3 main.py -t invalid.domain.fake -o scans/error_test.json
```

## Project Steps Performed

### Phase 1: Folder Structure Setup

```bash
mkdir -p TracerBatch && cd TracerBatch
touch main.py README.md
mkdir -p scans logs screenshots configs docs
```

### Phase 2: Script Development
- Used `argparse` for CLI input
- Used `platform.system()` to detect OS and choose traceroute/tracert
- Parsed raw traceroute output to extract hop IPs
- Saved traceroute results to `scans/` in JSON format
- Logged all activity and errors to `logs/debug.log`

### Phase 3: Validation & Testing

```bash
# Test 1: Single domain
python3 main.py -t scanme.nmap.org

# Test 2: Multiple domains
python3 main.py -t google.com cloudflare.com github.com -o scans/multi_trace.json

# Test 3: Invalid domain
python3 main.py -t invalid.domain.fake -o scans/error_test.json
```

- Output confirmed in `scans/*.json`
- Log file `logs/debug.log` confirmed creation
- Manual screenshots captured

### Phase 4: Screenshots Taken
- `screenshots/single_trace_output
