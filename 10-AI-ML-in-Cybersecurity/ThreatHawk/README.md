# ThreatHawk

## Description
ThreatHawk is an AI-powered log anomaly detection tool using Isolation Forest and TF-IDF vectorization. It detects suspicious log entries by learning normal log behavior from historical data. Ideal for SOC teams and automated SIEM pipelines, ThreatHawk supports CSV log ingestion and command-line interaction.

## Features
- Unsupervised anomaly detection with Isolation Forest
- TF-IDF feature extraction on log messages
- CLI interface with `--train` and `--detect`
- Model persistence with `joblib`
- Compatible with any CSV logs containing a 'message' column

## Installation
```bash
git clone https://github.com/mchyasn/cybersecurity-tools.git
cd 10-AI-ML-in-Cybersecurity/ThreatHawk
python3 -m venv venv
source venv/bin/activate
pip install pandas scikit-learn joblib
````

## Usage

### Train the model:

```bash
python3 src/threathawk.py --train
```

### Detect anomalies:

```bash
python3 src/threathawk.py --detect
```

### Help:

```bash
python3 src/threathawk.py --help
```

## Screenshots

![Screenshot](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/10-AI-ML-in-Cybersecurity/ThreatHawk/screenshots/0.png)
![Screenshot](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/10-AI-ML-in-Cybersecurity/ThreatHawk/screenshots/1.png)

## License

MIT

## Author

Author: mchyasn

