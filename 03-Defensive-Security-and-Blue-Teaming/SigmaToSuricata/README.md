# SigmaToSuricata

SigmaToSuricata is a powerful rule translation engine that converts Sigma detection rules into Suricata-compatible IDS rule syntax. It enables blue team engineers and detection developers to operationalize Sigma rules into real-world network security tools.

---

## Features

* Translates Sigma rules (YAML) into Suricata `.rules` format
* Field mapping engine via `mappings/sigma_to_suricata.json`
* Automatic rule conflict detection and deduplication
* Compatible with custom and community Sigma rules
* Built-in unit tests for every module

---

## Project Structure

```
SigmaToSuricata/
├── main.py                          # CLI runner for the tool
├── rule_translator.py              # Translates Sigma -> Suricata
├── rule_loader.py                  # Loads and parses Sigma YAML rules
├── field_mapper.py                 # Maps Sigma fields to Suricata equivalents
├── conflict_resolver.py            # Removes rule duplicates
├── utils.py                        # Shared utility functions
├── requirements.txt                # Dependencies
├── README.md                       # Tool documentation
│
├── mappings/
│   └── sigma_to_suricata.json      # Field mapping file
├── rules/
│   └── example_sigma_rule.yml      # Example Sigma input rule
├── output/
│   └── translated_suricata.rules   # Final output rules for Suricata
├── tests/
│   ├── test_rule_loader.py         # Unit tests for rule loader
│   ├── test_rule_translator.py     # Unit tests for translator
│   ├── test_field_mapper.py        # Unit tests for field mapping
│   └── test_conflict_resolver.py   # Unit tests for conflict resolver
├── screenshots/                    # Test screenshots and outputs
```

---

## Usage

### 1. Activate virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Translate Sigma rules

```bash
python3 main.py \
  --input rules/ \
  --output output/translated_suricata.rules \
  --mapping mappings/sigma_to_suricata.json
```

---

## Run Tests

```bash
python3 -m unittest discover tests
```

---

## Screenshots

Save screenshots from real usage into the `screenshots/` folder for documentation, including translated `.rules` outputs and test logs.

---

## Author

Created by **mchyasn**

---

## License

MIT License
