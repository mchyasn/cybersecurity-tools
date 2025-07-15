# ServiceCertGrabber

## Description
ServiceCertGrabber is a TLS certificate reconnaissance and fingerprinting tool. It connects to target hosts over SSL/TLS, extracts the complete certificate chain, captures expiration metadata, and generates structured output in JSON format. Designed for use in threat intelligence workflows, it also includes optional JA3 fingerprinting support for future malware C2 identification and passive fingerprinting enhancements.

## Features
- Retrieves full TLS/SSL certificate chain from target IP/domain
- Extracts issuer, subject, serial, expiry, and SAN details
- Saves structured scan output as JSON in `scans/`
- Logging support with detailed debug info saved in `logs/debug.log`
- Supports future JA3 fingerprinting integration (field reserved)
- Configurable via YAML file in `configs/config.yaml`

## Installation
```bash
git clone https://github.com/yourusername/ServiceCertGrabber.git
cd ServiceCertGrabber
pip install -r requirements.txt
````

## Usage

```bash
# Basic TLS scan
sudo python3 main.py google.com

# Scan a custom port
sudo python3 main.py github.com --port 8443

# Output is saved to scans/certgrab_<host>_<port>_<timestamp>.json
```

## Project Steps Performed

### Phase 1: Folder Structure

Created the following folder layout:

```
ServiceCertGrabber/
├── main.py
├── README.md
├── configs/
│   └── config.yaml
├── logs/
│   └── debug.log (generated at runtime)
├── scans/
│   └── certgrab_<target>_<timestamp>.json
├── screenshots/  # Empty unless used for screenshots
```

### Phase 2: Script Development

* Built a robust TLS scanner using Python's `ssl` and `socket` libraries
* Configurable timeout, port, and target via argparse
* Captures cert metadata, timestamps the results, and stores to scans/
* Ensured logging and error handling are recorded in logs/debug.log

### Phase 3: Testing & Validation

* Example test:

```bash
sudo python3 main.py google.com
```

## Screenshots

![SSL Certificate Collector](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/01-Network-Scanning-and-Reconnaissance/ServiceCertGrabber/screenshots/0.png)


## License

MIT

## Author

## mchyasn
