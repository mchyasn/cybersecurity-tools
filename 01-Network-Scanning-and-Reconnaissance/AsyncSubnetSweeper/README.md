# AsyncSubnetSweeper

## Description
AsyncSubnetSweeper is a high-performance asynchronous subnet scanner that leverages ICMP echo requests and TCP SYN probes to discover live hosts within a subnet. Designed with protocol compliance and stealth in mind, it uses rate limiting and jitter to evade IDS systems. The tool reads scanning configurations from a YAML file and outputs results in structured JSON or CSV formats. It also features direct chaining to SmartPortMap for post-discovery port scanning without intermediate files.

## Features
- ICMP echo (raw socket) and TCP SYN (stealth) pinging
- Fully asynchronous with token-bucket rate limiting
- Configurable via `configs/config.yaml`
- Output formats: JSON or CSV
- Stealth scanning with jittered delays
- Direct integration with SmartPortMap (optional)
- Validated YAML-based configuration via Pydantic
- Clean, machine-readable output for further automation

## Installation
```bash
git clone https://github.com/yourusername/AsyncSubnetSweeper.git
cd AsyncSubnetSweeper
pip install -r requirements.txt
````

## Usage

```bash
# Basic scan using defaults from configs/config.yaml
sudo python3 main.py 192.168.1.0/24

# Specify rate limit and output format
sudo python3 main.py 192.168.1.0/24 --rate 100 --output csv

# Disable SmartPortMap chaining
sudo python3 main.py 192.168.1.0/24 --no-smartport

# Use custom config file
sudo python3 main.py 192.168.1.0/24 --config configs/custom.yaml
```

## Project Steps Performed

### Phase 1: Folder Structure

```
AsyncSubnetSweeper/
├── main.py
├── README.md
├── configs/
│   └── config.yaml
├── logs/
│   └── debug.log (generated at runtime)
├── scans/
│   └── scan_output.json|csv
├── screenshots/
│   └── usage.png (manual)
```

### Phase 2: Script Development

* ICMP echo requests via raw sockets (root required)
* TCP SYN-based liveness detection (fallback)
* TokenBucket class for rate limiting
* Fully async sweep using asyncio.gather
* CLI overrides for YAML config values
* Chaining logic for SmartPortMap via subprocess

### Phase 3: Testing & Validation

**Test Command**

```bash
sudo python3 main.py 192.168.1.0/24 --rate 100 --output json
```

**Screenshot Instruction**

* After scan completes and prints `live hosts found`, take a screenshot and save as:
  `screenshots/scan_result.png`

### Phase 4: README.md Generation

* Current document

## Screenshots
![Asynchronous Subnet Scanner](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/01-Network-Scanning-and-Reconnaissance/AsyncSubnetSweeper/screenshots/0.png)
![Asynchronous Subnet Scanner](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/01-Network-Scanning-and-Reconnaissance/AsyncSubnetSweeper/screenshots/1.png)
![Asynchronous Subnet Scanner](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/01-Network-Scanning-and-Reconnaissance/AsyncSubnetSweeper/screenshots/2.png)

## License

MIT

## Author

### mchyasn
