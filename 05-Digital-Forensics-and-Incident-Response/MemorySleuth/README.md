# MemorySleuth

**MemorySleuth** is a modular live and dead memory forensics framework designed for post-exploitation analysis, credential recovery, malware detection, and advanced memory inspection. It supports integration with Volatility3, YARA, and custom dump parsers for both standard and unconventional memory artifacts.

---

## Overview

MemorySleuth provides a safe and extensible way to analyze memory dumps using pluggable modules. It is intended for red teamers, malware analysts, and forensic investigators looking to:

* Parse memory images acquired from compromised or test systems
* Identify credential artifacts, malicious processes, and suspicious behavior
* Automate post-exploitation triage with detection rules
* Extend analysis with custom Volatility plugins or binary extractors

---

## Features

* Live and offline memory analysis support
* Volatility3 integration for modular memory plugin scanning
* YARA scanning against entire memory blobs
* Supports future Rekall, WinDbg, and LSASS-specific parsers
* Full CLI interface with YAML-driven configuration
* Sandbox-safe: all tests performed on fake or dummy dumps unless specified

---

## Example Usage

```bash
source venv/bin/activate
python3 main.py dumps/fake.raw --config config/sleuth.yml
```

This will:

* Run Volatility3 plugins defined in the config
* Run a YARA scan on the raw memory file
* Display results in the console

---

## Configuration File

Located at: `config/sleuth.yml`

```yaml
run_volatility: true
run_yara: true

volatility_plugins:
  - windows.pslist.PsList
  - windows.cmdline.CmdLine
  - windows.hashdump.HashDump

yara_rules:
  - rules/malware.yar
```

You can disable either engine by toggling the respective key.

---

## Tool Architecture

```
MemorySleuth
├── main.py                  # Entry point
├── config/                  # YAML config and loader
├── modules/                 # Core logic and scanners
│   ├── controller.py        # Execution logic
│   └── yara_scanner.py      # YARA integration
├── parsers/                # Future: LSASS/WinDbg/Rekall custom parsers
├── rules/                  # YARA rules
├── dumps/                  # Memory images to be scanned
├── logs/                   # Output or cache logs
├── tests/                  # Unittest support
├── screenshots/            # Demo screenshots
└── requirements.txt        # Python dependencies
```

---

## Output Expectations

* Volatility3 plugin results are printed per plugin to stdout
* YARA matches (if any) are shown with match names
* Volatility errors (if using fake or invalid dumps) are gracefully handled

---

## Testing

Basic unit test included:

```bash
python3 -m unittest discover tests
```

Sample test verifies that invalid memory dumps are caught and handled without crashing the tool.

---

## Integration Notes

* Volatility3 is directly invoked as a Python module
* Volatility plugins must be passed as positional arguments (one per run)
* YARA rule files must be valid and parsable by yara-python
* `logs/vol_cache` is used to store Volatility caches for reuse
* More parsers can be added to `parsers/` using shared memory APIs

---

## Screenshots

Add live CLI output screenshots here to demonstrate analysis output.

---

## Author

Built by **mchyasn**
Toolset designed for serious post-exploitation workflows, purple team validation, and malware research.
