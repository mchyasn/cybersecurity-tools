# AutoHoneynet

## Description

AutoHoneynet is a deployable honeynet orchestration tool designed to spin up containerized decoy services for attacker engagement. It supports multiple honeypots such as SSH (Cowrie) and HTTP traps, while logging malicious activity in a structured format. The logs are compatible with tools like LogSentinel and AutoIR-Playbook for alerting and response chaining.

## Features

* Docker Compose orchestration of honeypots
* Live monitoring and log parsing
* YAML-configurable trap behavior
* Alerts to console with timestamped event markers
* Integration-ready with LogSentinel and AutoIR frameworks

## Installation

```bash
git clone https://github.com/yourname/AutoHoneynet.git
cd AutoHoneynet
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python3 main.py \
  --config configs/config.yaml \
  --mode deploy

python3 main.py \
  --config configs/config.yaml \
  --mode monitor
```

## Configuration

See `configs/config.yaml` for log output path and deployment mode.

## Screenshots

![Usage](screenshots/deployment.png)
![Log Monitor](screenshots/monitoring.png)

## License

MIT

## Disclaimer

For authorized testing only.

## Author

mchyasn
