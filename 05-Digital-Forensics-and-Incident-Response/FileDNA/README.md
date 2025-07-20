# FileDNA

FileDNA is a malware hashing and similarity engine designed for rapid profiling of unknown PE files. It extracts key features, calculates fuzzy hashes, performs YARA matches, and integrates with VirusTotal or a local malware zoo.

## Features

* Extracts PE metadata: MD5, imphash
* Computes ssdeep fuzzy hashes
* Runs YARA rule matches
* Outputs CSV reports for all analyzed files
* Modular controller logic
* Compatible with local malware sample directories
* Designed for offline and local malware zoo analysis
* Easily extendable with custom YARA rules or hashing methods

## Example Usage

```bash
source venv/bin/activate
python3 main.py samples --config config/filedna.yml
```

## Configuration (config/filedna.yml)

```yaml
sample_path: samples
yara_rules:
  - rules/suspicious.yar
output_path: output/filedna_report.csv
log_file: logs/filedna.log
```

## Folder Structure

```
FileDNA/
├── config/
│   └── filedna.yml
├── logs/
│   └── filedna.log
├── modules/
│   ├── controller.py
│   ├── peinfo.py
│   ├── yara_matcher.py
│   └── hash_utils.py
├── output/
│   └── filedna_report.csv
├── rules/
│   └── suspicious.yar
├── samples/
│   └── fake.exe
├── screenshots/
│   └── 0.png
├── tests/
│   └── test_controller.py
├── main.py
├── requirements.txt
└── README.md
```

## Screenshot

![Malware Hashing Report](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/05-Digital-Forensics-and-Incident-Response/FileDNA/screenshots/0.png)

## Author

Built by mchyasn
Designed for malware analysts, threat researchers, and reverse engineers.
