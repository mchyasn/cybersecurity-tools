# ShadowSpray

Credential Spraying + MFA Bypass Toolkit

ShadowSpray is a red team utility designed to simulate realistic password spraying attacks across modern identity platforms. It also supports bypassing weak or misconfigured MFA protections.

## Features

* Low-and-slow password spraying to avoid detection and lockout
* Target support:

  * Microsoft 365
  * Okta
  * OpenVPN
  * Generic/custom webapps
* MFA evasion techniques (e.g., no IP restriction, session prediction)
* Proxy and user-agent rotation support
* Custom delay between attempts
* Result logging to CSV

## Folder Structure

```
ShadowSpray/
├── config/
│   ├── target.yml
│   └── proxies.txt
├── modules/
│   └── sprayer.py
├── output/
│   └── results.csv
├── main.py
├── requirements.txt
└── screenshots/
    ├── 0.png
    └── 1.png
```

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python3 main.py --config config/target.yml --delay 10 --verbose --output output/results.csv --proxy-file config/proxies.txt
```

## Configuration

Edit `config/target.yml`:

```yaml
- url: "https://example.com/login"
  method: POST
  login_data:
    username: "{user}"
    password: "{pass}"
  fail_keyword: "Invalid login"
  usernames:
    - "admin@example.com"
    - "user1@example.com"
  passwords:
    - "Winter2024!"
    - "Password123!"
```

**Note:** Replace `example.com` with your real target (e.g., `login.microsoftonline.com`). Ensure `fail_keyword` matches the string returned on failed login attempts.

## Screenshots

![ShadowSpray](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/09-Authentication-and-Access-Bypass-Simulators/ShadowSpray/screenshots/0.png)
![ShadowSpray](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/09-Authentication-and-Access-Bypass-Simulators/ShadowSpray/screenshots/1.png)

## Author

Created by mchyasn
