# ModelShield

## Description
ModelShield is a machine learning-powered adversarial input detector that identifies anomalous inputs designed to evade traditional classifiers. It uses Isolation Forest with StandardScaler preprocessing to model normal input behavior and flag abnormal samples based on statistical deviation. This tool is ideal for securing ML pipelines and detecting adversarial test-time evasion.

## Features
- Detects adversarial or anomalous inputs
- Unsupervised model using Isolation Forest
- Standardized numerical feature inputs
- CLI interface for training and scoring
- Works on CSV files with numeric features only

## Installation
```bash
git clone https://github.com/mchyasn/cybersecurity-tools.git
cd 10-AI-ML-in-Cybersecurity/ModelShield
python3 -m venv venv
source venv/bin/activate
pip install pandas scikit-learn joblib numpy
````

## Usage

### Train detector on clean data:

```bash
python3 src/modelshield.py --train
```

### Score new samples:

```bash
python3 src/modelshield.py --score --input data/test_samples.csv
```

### Help:

```bash
python3 src/modelshield.py --help
```

## Screenshots

![Screenshot](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/10-AI-ML-in-Cybersecurity/ModelShield/screenshots/0.png)

## License

MIT

## Author

Author: mchyasn
