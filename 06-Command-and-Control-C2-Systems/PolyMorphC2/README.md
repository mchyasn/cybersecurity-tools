# PolyMorphC2


## Description

**PolyMorphC2** is a polymorphic command-and-control framework designed to evade EDR detection using advanced payload mutation techniques. It features an in-memory payload loader, a customizable mutation engine (e.g., XOR-based), and a beacon module capable of jittered C2 check-ins. This tool is ideal for red teamers and exploit developers testing stealth delivery and process injection.

## Features

* Polymorphic payload mutation on every launch
* Loader supports in-memory execution and injection simulation
* Beacon module with randomized jitter intervals
* PE parsing utilities for future enhancements
* Simple configuration via YAML

## Installation

```bash
git clone https://github.com/your/repo.git
cd PolyMorphC2
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Usage

### Run the loader and mutate shellcode:

```bash
python3 main.py --config configs/config.yaml
```

Expected:

```
[!] Simulated injection into notepad.exe with 101 bytes
```

### Run the beacon loop (debugging):

```bash
python3 beacon/beacon.py
```

Expected output:

```
[!] Beacon failed: Connection refused (if no C2 is listening)
```

## Configuration

`configs/config.yaml`:

```yaml
loader:
  inject_method: "remote_thread"
  mutation: true
  target_process: "notepad.exe"

beacon:
  interval: 10
  jitter: 0.3
```

* `mutation`: enables polymorphic transformation of shellcode
* `target_process`: simulated injection target
* `interval/jitter`: controls beacon check-in frequency

## Screenshots

![PolyMorphC2](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/06-Command-and-Control-C2-Systems/PolyMorphC2/screenshots/0.png)
![PolyMorphC2](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/06-Command-and-Control-C2-Systems/PolyMorphC2/screenshots/1.png)

## License

MIT

## Disclaimer

🔥 For educational use only. Do not run without authorization.

## Author

\[mchyasn]
