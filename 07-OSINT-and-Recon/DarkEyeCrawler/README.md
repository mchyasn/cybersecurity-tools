# DarkEyeCrawler


## Description

**DarkEyeCrawler** is a dark web and leak monitoring tool designed to scrape pastebin clones, GitHub, and Onion service mirrors for exposed credentials, domains, or keywords of interest. It simulates real breach intelligence workflows by detecting potentially leaked content and optionally triggering alerts via Slack or email. This is ideal for demonstrating dark web recon, breach monitoring, and credential exposure detection use cases.

## Features

* Scans pastebin clones and public GitHub search
* Onion site list included for future Tor-based crawling
* Keyword-based leak detection
* Alert delivery to Slack or other integrations
* Configurable sources and keywords

## Installation

```bash
git clone https://github.com/your/repo.git
cd DarkEyeCrawler
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Usage

```bash
python3 main.py -k password,admin,confidential
```

Example output:

```
[!] Leak match: Found 'admin' on https://pastebin.pl
[!] Leak match: Found 'password' on GitHub search
```

## Configuration

`configs/config.yaml`:

```yaml
sources:
  onion_sites:
    - "http://exampleonion123.onion"
    - "http://dump4freeonion.onion"
  paste_clones:
    - "https://paste.gg"
    - "https://pastebin.pl"
  github_search:
    enabled: true

alerting:
  slack_webhook: ""
  email_enabled: false
```

* `onion_sites`: placeholder for Tor scraping expansion
* `paste_clones`: regular web paste mirrors
* `github_search`: enable public code search
* `slack_webhook`: send alerts to Slack if filled

## Screenshots

![DarkEyeCrawler](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/07-OSINT-and-Recon/DarkEyeCrawler/screenshots/0.png)
![DarkEyeCrawler](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/07-OSINT-and-Recon/DarkEyeCrawler/screenshots/1.png)

## License

MIT

## Disclaimer

🔥 For educational use only. Do not run without authorization.

## Author

\[mchyasn]
