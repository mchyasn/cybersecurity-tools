# IntelScope

## Description

**IntelScope** is a company and employee reconnaissance tool designed to extract names, emails, and user identifiers from public sources like LinkedIn and Crunchbase. It enriches the data using email pattern formats and outputs a CSV file ready for use in phishing campaigns, password spraying, or red team infrastructure setups. This simulates real-world APT-style recon workflows.

## Features

* Scrapes names from Bing-indexed LinkedIn profiles
* Simulated Crunchbase executive scraping
* Email enrichment with configurable formatting
* Outputs clean CSV for phishing/spray ops
* Easy to extend and plug into recon pipelines

## Installation

```bash
git clone https://github.com/your/repo.git
cd IntelScope
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Usage

```bash
python3 main.py -c acme-corp -o output/employees.csv
```

Example output:

```
[+] Collecting data for: acme-corp
[+] Scraped LinkedIn: ['https://linkedin.com/in/john-smith']
[+] Scraped Crunchbase: ['Acme - Sample Exec 1']
[+] Parsed 2 employees
[+] Saved to: output/employees.csv
```

## Configuration

`configs/config.yaml`:

```yaml
sources:
  linkedin_scrape: true
  crunchbase_scrape: true

enrichment:
  default_domain: "example.com"
  email_format: "{first}.{last}@{domain}"
```

* Supports different email formats: `f.last`, `first_last`, etc.
* Default domain used for email construction

## Screenshots

![IntelScope](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/07-OSINT-and-Recon/IntelScope/screenshots/0.png)
![IntelScope](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/07-OSINT-and-Recon/IntelScope/screenshots/1.png)

## License

MIT

## Disclaimer

🔥 For educational use only. Do not run without authorization.

## Author

\[mchyasn]
