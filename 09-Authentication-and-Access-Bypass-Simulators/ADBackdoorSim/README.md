# ADBackdoorSim

**Simulates Authentication Backdoors in Active Directory Environments**

---

## Overview

`ADBackdoorSim` is a red team simulation and detection lab tool designed to demonstrate three powerful techniques for backdooring Active Directory:

* **SIDHistory Injection**
* **AdminSDHolder Abuse**
* **ACL-based Persistence**

This tool enables purple teams to emulate stealthy, long-term persistence tactics and validate defensive visibility using event logs, audit policies, or BloodHound-style detections.

---

## Features

*  Simulates SIDHistory injection to escalate privileges.
*  Demonstrates AdminSDHolder overwrites.
*  Abuses ACL permissions to maintain persistent access.
*  Supports YAML-based configuration for flexibility.
*  Works against live AD with valid credentials.

---

## Folder Structure

```
ADBackdoorSim/
├── config/
│   └── target.yml
├── modules/
│   ├── sid_history.py
│   ├── sdholder.py
│   └── acl_backdoor.py
├── output/
│   └── report.csv
├── screenshots/
├── tests/
│   └── test_sid_history.py
├── logs/
│   └── adbackdoor.log
├── main.py
├── requirements.txt
└── README.md
```

---

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Configuration Example (`config/target.yml`)

```yaml
ldap_server: "192.168.56.10"
domain: "corp.local"
bind_dn: "CN=Administrator,CN=Users,DC=corp,DC=local"
password: "P@ssw0rd123"
target_dn: "CN=User1,CN=Users,DC=corp,DC=local"
sid_to_inject: "S-1-5-21-1111111111-2222222222-3333333333-500"
```

---

## Usage

```bash
# SIDHistory injection
python3 main.py --config config/target.yml --method sid --verbose

# AdminSDHolder abuse
python3 main.py --config config/target.yml --method sdholder --verbose

# ACL-based backdoor
python3 main.py --config config/target.yml --method acl --verbose
```

---

## Author

Created by **mchyasn**

---

## License

For educational and research use only.
