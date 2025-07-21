# TokenTrickster

---

## Features

* Enumerates current process token information
* Lists user SID and available privileges
* Simulates SYSTEM/admin impersonation logic
* Optionally spawns `cmd.exe` with current token
* Colorized console interface (via colorama)

---

## Folder Structure

```
TokenTrickster/
├── config/
│   └── config.yml
├── logs/
│   └── log.txt
├── modules/
│   └── token_utils.py
├── output/
├── screenshots/
│   ├── 0.png
│   └── 1.png
├── main.py
└── requirements.txt
```

---

## Installation (on Windows Only)

### 1. Ensure Python 3.10+ is Installed with PATH set

### 2. Create and activate a virtual environment:

```powershell
cd TokenTrickster
python -m venv venv
.env\Scripts\activate
```

### 3. Install requirements:

```powershell
pip install -r requirements.txt
pip install PyYAML
```

---

## Usage

```powershell
python main.py
```

### Menu Options:

* **(1)** List token info (SID, privileges)
* **(2)** Simulate SYSTEM impersonation logic
* **(3)** Spawn new `cmd.exe` under current token (if allowed)
* **(4)** Exit

---

## Screenshots

![Token Info Output](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/09-Authentication-and-Access-Bypass-Simulators/TokenTrickster/screenshots/0.png)
![SYSTEM Impersonation Simulation](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/09-Authentication-and-Access-Bypass-Simulators/TokenTrickster/screenshots/1.png)
![SYSTEM Impersonation Simulation](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/09-Authentication-and-Access-Bypass-Simulators/TokenTrickster/screenshots/2.png)


---

## Author

Created by [mchyasn](https://github.com/mchyasn)

---

## License

This project is for educational and research purposes only. Use it in controlled environments only.
