# NetMetaScan – Metadata Enumerator for Network Services

## Description

**NetMetaScan** is an advanced network metadata scanner built for Blue Teams, SOC analysts, and cybersecurity practitioners who need to detect exposed service information, version leaks, and misconfigurations. The tool supports a wide variety of common protocols and captures valuable metadata such as TLS certificate information and service banners in automation-friendly JSON format.

It is designed for clean integration in pipelines, forensic collection, or triage tasks.

## Features

* Supports scanning of HTTP, HTTPS, SSH, FTP, SMTP, POP3, and RDP services
* Extracts **TLS certificate metadata** (subject, issuer, expiration)
* Captures **service banners** and version details (if exposed)
* Optional **JA3 TLS fingerprinting** with `--enable-ja3` flag
* Structured JSON output with built-in **JSON Schema validation**
* Modular scanner registry via **decorator pattern**
* Stores detailed logs in `logs/debug.log` for each scan
* Fully asynchronous (uses Python asyncio for performance)
* Automation-ready and safe for integration in CI pipelines

## Installation

```bash
git clone https://github.com/yourusername/NetMetaScan.git
cd NetMetaScan
pip install -r requirements.txt
```

> Requires Python 3.8+
> JA3 functionality works best on Linux and requires `ssl` and `hashlib` (default in Python).

## Usage

```bash
python3 main.py -t targets.txt -o scans --enable-ja3
```

### Arguments

| Flag                  | Description                                                  |
| --------------------- | ------------------------------------------------------------ |
| `-t`, `--targets`     | File containing list of targets (one `host[:port]` per line) |
| `-o`, `--output`      | Output directory for scan results (default: `scans/`)        |
| `-c`, `--concurrency` | Maximum concurrent scans (default: 100)                      |
| `--timeout`           | Timeout per connection attempt (default: 5.0s)               |
| `--enable-ja3`        | Enable basic JA3 fingerprinting for TLS                      |

### Example Target File

```
scanme.nmap.org
example.com:22
```

> If the port is omitted, the tool uses the protocol’s default port.

## Project Steps Performed

### Phase 1 – Core Scanner Implementation

* Developed base class `BaseScanner` for uniform scanner behavior
* Integrated `asyncio` and semaphore for parallel scanning

### Phase 2 – Protocol Scanners

* Implemented scanners for:

  * **HTTP/HTTPS**: Banner and TLS metadata extraction
  * **SSH**: Simple banner grab
  * **FTP/POP3/SMTP**: Service banner detection
  * **RDP**: Initial handshake & hex output
* Registered all scanners via a `@register_protocol` decorator

### Phase 3 – Metadata Handling

* Extracted fields like:

  * `server`, `x-powered-by` from HTTP headers
  * `tls_subject`, `tls_issuer`, `tls_expiration` from certificates

### Phase 4 – Output Handling

* Output saved as structured JSON files under `scans/`
* Built-in schema validation via `jsonschema` for consistent formatting
* Logging added to `logs/debug.log` with INFO/WARNING levels

### Phase 5 – JA3 Fingerprinting

* Basic TLS cipher-based fingerprinting (optional)
* Enabled via `--enable-ja3` flag

## Screenshots

### Example Output JSON

```json
[
  {
    "host": "scanme.nmap.org",
    "protocol": "https",
    "port": 443,
    "tls_subject": [["commonName", "scanme.nmap.org"]],
    "tls_issuer": [["commonName", "Let's Encrypt"]],
    "tls_expiration": "Jul 27 23:59:59 2025 GMT"
  },
  {
    "host": "scanme.nmap.org",
    "protocol": "ssh",
    "port": 22,
    "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3"
  }
]
```

### Example Log Output (logs/debug.log)

```
2025-07-14 21:40:01 [INFO] scanme.nmap.org:443 [https] success
2025-07-14 21:40:01 [INFO] scanme.nmap.org:22 [ssh] success
2025-07-14 21:40:01 [WARNING] scanme.nmap.org:21 [ftp] failed: ConnectionRefusedError
```

## Author

Author: mchyasn
