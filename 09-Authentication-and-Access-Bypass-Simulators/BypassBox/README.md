# BypassBox

**BypassBox** is a web authentication bypass simulator designed to test and demonstrate common weaknesses in JWT, OAuth, and SAML token validation mechanisms. It mimics real-world vulnerabilities and simulates attacks like algorithm confusion, token expiry bypass, and cookie/session fixation.

---

## Features

* JWT None Algorithm Attack
* Algorithm Confusion (RS256 → HS256)
* Expired Token Replay
* Session Fixation and Cookie Injection
* YAML config-driven inputs
* Works on any REST API / web app with token-based auth

---

## Folder Structure

```
BypassBox/
├── config/
│   └── config.yml
├── logs/
│   └── log.txt
├── modules/
│   ├── alg_confusion.py
│   ├── expired_replay.py
│   ├── none_alg.py
│   └── session_fixation.py
├── output/
├── screenshots/
│   └── 0.png
├── main.py
└── requirements.txt
```

---

## Installation

```bash
cd BypassBox
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Configuration

Edit `config/config.yml` to set:

```yaml
jwt_token: "<your_base64_jwt_here>"
target_url: "https://example.com/protected"
cookie_name: "auth_token"
```

---

## Usage

```bash
python main.py
```

Choose from:

* **(1)** None-alg JWT token crafting
* **(2)** RS256 → HS256 confusion
* **(3)** Expired token replay
* **(4)** Cookie injection / session fixation

---

## Screenshot

![BypassBox Demo](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/09-Authentication-and-Access-Bypass-Simulators/BypassBox/screenshots/0.png)

---

## Author

Created by [mchyasn](https://github.com/mchyasn)

---

## License

This tool is for research and educational use only. Use it only in environments you are authorized to test.
