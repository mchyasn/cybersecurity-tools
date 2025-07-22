# PassTheWhatever

**PassTheWhatever** is a modular NTLM and Kerberos-based authentication bypass suite. It simulates well-known attacks such as Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash, and Kerberoasting. It mimics tools like Mimikatz and Impacket's ntlmrelayx, helping red teamers and blue teamers study credential abuse and ticket manipulation scenarios.

---

## Features

* ✅ Pass-the-Hash using Impacket SMBConnection
* ✅ Pass-the-Ticket (simulated via mimikatz wrapper)
* ✅ Overpass-the-Hash (simulated)
* ✅ Kerberoasting logic (simulation)
* ✅ Interactive CLI with color-coded output

---

## Folder Structure

```
PassTheWhatever/
├── config/
│   └── config.yml
├── logs/
│   └── log.txt
├── modules/
│   ├── kerberoast.py
│   ├── opth.py
│   ├── pth.py
│   └── ptt.py
├── output/
│   └── ticket.kirbi
├── screenshots/
│   └── 0.png
├── main.py
└── requirements.txt
```

---

## Installation

### Linux or Windows (Python 3.10+)

```bash
cd PassTheWhatever
python3 -m venv venv
source venv/bin/activate  # Windows: .\venv\Scripts\activate
pip install -r requirements.txt
pip install PyYAML colorama
```

### Install Impacket from Source (required for PTH):

```bash
cd ~
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
python3 setup.py install
```

---

## Usage

```bash
python main.py
```

You will see:

```
[+] PassTheWhatever - Auth Bypass Suite

(1) Pass-the-Hash
(2) Pass-the-Ticket
(3) Overpass-the-Hash
(4) Kerberoasting Simulation
(5) Exit
```

---

## Screenshots

![Tool Menu](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/09-Authentication-and-Access-Bypass-Simulators/PassTheWhatever/screenshots/0.png)

---

## Notes

* PTH uses SMB login with NTLM hash
* PTT expects mimikatz.exe available in PATH (Windows only)
* OPTH and Kerberoasting are safe simulated demos

---

## Author

Created by [mchyasn](https://github.com/mchyasn)

---

## License

This project is for research and educational purposes only. Use in authorized environments only.
