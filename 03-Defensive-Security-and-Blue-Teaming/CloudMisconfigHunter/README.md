# CloudMisconfigHunter

## Description

CloudMisconfigHunter is a multi-cloud misconfiguration scanner that detects common exposure and access issues across AWS, GCP, and Azure. It checks for public storage buckets, exposed APIs, and insecure IAM configurations. Alerts are written in a consistent format for downstream processing or ingestion into SOAR workflows.

## Features

* AWS: S3 public access and IAM enumeration checks
* GCP: Public bucket access and open API endpoint detection
* Azure: Blob container exposure and API availability scan
* Alert logging to file (alerts.txt)
* CLI and config-driven execution

## Installation

```bash
git clone https://github.com/yourrepo/CloudMisconfigHunter.git && cd CloudMisconfigHunter
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python3 src/main.py \
  --config configs/config.yaml \
  --target aws
```

## Configuration

See `configs/config.yaml` for bucket names, test API URLs, and future webhook configs.

## Screenshots

![Cloud Security Posture Scanner](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/03-Defensive-Security-and-Blue-Teaming/CloudMisconfigHunter/screenshots/0.png)

## License

MIT

## Disclaimer

For authorized testing only.

## Author

mchyasn
