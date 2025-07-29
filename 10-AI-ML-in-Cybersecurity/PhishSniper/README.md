# PhishSniper

## Description
PhishSniper is an AI-powered phishing URL detection tool designed for blue team analysts, SOC engineers, and automation pipelines. It uses TF-IDF vectorization and Logistic Regression to detect malicious or benign URLs from labeled datasets. The tool supports training a model from CSV data and running single URL predictions via command-line.

## Features
- CLI-based training and prediction
- TF-IDF feature extraction on URLs
- Logistic Regression classification
- Joblib-based model saving/loading
- Error handling and validation for missing files/columns

## Installation
```bash
git clone https://github.com/mchyasn/cybersecurity-tools.git
cd 10-AI-ML-in-Cybersecurity/PhishSniper
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install pandas scikit-learn joblib
````

## Usage

### Train the model:

```bash
python3 src/phishsniper.py --train
```

### Predict a single URL:

```bash
python3 src/phishsniper.py --predict http://malicious-domain.biz/phish.html
```

### View help:

```bash
python3 src/phishsniper.py --help
```

## Screenshots

![Screenshot](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/10-AI-ML-in-Cybersecurity/PhishSniper/screenshots/0.png)

## License

MIT

## Author

Author: mchyasn

```
```
