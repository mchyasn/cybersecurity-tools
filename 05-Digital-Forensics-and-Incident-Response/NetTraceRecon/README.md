# NetTraceRecon

**NetTraceRecon** is a powerful network forensics parser that analyzes PCAP files and live network traffic to extract valuable forensic data. It supports automatic IOC extraction, session reconstruction, DNS parsing, credential harvesting, and file transfer analysis. Built for DFIR professionals, it integrates seamlessly with **AutoIR** and **LogSentinel** for real-time detection and response.

---

## Key Features

* Parses PCAPs and live interfaces using Pyshark and Scapy
* Extracts sessions, credentials, DNS, file transfers
* Supports IOC extraction and automatic tagging
* Parses Zeek logs and Suricata alerts
* Outputs structured artifacts and IOCs in CSV
* Compatible with AutoIR-Playbook and LogSentinel

---

## Configuration File (YAML)

**`config/nettrace.yml`**

```yaml
pcap_mode: true
interface: eth0
extract_sessions: true
extract_dns: true
extract_credentials: true
extract_files: true
parse_zeek_logs: true
parse_suricata_alerts: true
export_iocs: true
```

---

## Usage

### 1. Activate Virtual Environment

```bash
source venv/bin/activate
```

### 2. Analyze PCAP File

```bash
python3 main.py --pcap traces/fake.pcap --config config/nettrace.yml
```

> Live capture currently disabled due to missing pyshark support in sudo context.

---

## Folder Structure

```
NetTraceRecon/
├── config/
│   └── nettrace.yml
├── logs/
│   └── nettrace.log
├── modules/
│   ├── controller.py
│   ├── ioc_extractor.py
│   └── pcap_parser.py
├── output/
│   └── iocs.csv
├── screenshots/
│   └── 0.png
├── tests/
│   └── test_controller.py
├── traces/
│   └── fake.pcap
├── main.py
├── requirements.txt
└── README.md
```

---

## Screenshot

![NetTraceRecon](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/05-Digital-Forensics-and-Incident-Response/NetTraceRecon/screenshots/0.png)

---

## Author

Built by **mchyasn**
Designed for forensic analysts and network incident responders.
