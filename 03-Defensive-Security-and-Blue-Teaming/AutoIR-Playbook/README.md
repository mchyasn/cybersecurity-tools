# AutoIR-Playbook

## Description

AutoIR-Playbook is a YAML-driven incident response automation framework that simulates real-world response workflows using modular playbooks. It supports shell command execution, file actions, and tagging alerts in sequence to model security response automation. This tool is useful for demonstrating SOAR-style logic, DevOps security fusion, and modular IR thinking.

## Features

* Executes YAML-defined playbooks step by step
* Supports shell commands, file copy/delete, tagging alerts
* Includes dry-run mode for simulation
* Validates required fields and action types
* Logs actions to file and console

## Installation

```bash
git clone https://github.com/yourrepo/AutoIR-Playbook.git && pip install -r requirements.txt  
```

## Usage

```bash
sudo python3 src/main.py \
  --config configs/config.yaml \
  --playbook docs/example-playbook.yaml \
  --dry-run  
```

## Configuration

See `configs/config.yaml` for settings.

## Screenshots

![Usage](screenshots/usage.png)

## License

MIT

## Disclaimer

For authorized testing only.

## Author

mchyasn
