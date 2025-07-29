# EmailSentry

## Description
EmailSentry is an AI-driven phishing email classifier that uses natural language processing and logistic regression to determine if an email is phishing or benign. Designed for SOC teams and email security gateways, it supports command-line prediction using either raw email strings or `.txt` files. The model is trained on labeled datasets with TF-IDF feature extraction.

## Features
- Phishing vs benign email classification
- TF-IDF + Logistic Regression pipeline
- Accepts raw strings or file input
- CSV-based training with labeled email text
- CLI support for training and prediction

## Installation
```bash
git clone https://github.com/mchyasn/cybersecurity-tools.git
cd 10-AI-ML-in-Cybersecurity/EmailSentry
python3 -m venv venv
source venv/bin/activate
pip install pandas scikit-learn joblib
````

## Usage

### Train the model:

```bash
python3 src/emailsentry.py --train
```

### Predict from string:

```bash
python3 src/emailsentry.py --predict "Click here to verify your PayPal account"
```

### Predict from .txt file:

```bash
python3 src/emailsentry.py --predict sample_email.txt
```

## Screenshots

![Screenshot](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/10-AI-ML-in-Cybersecurity/EmailSentry/screenshots/0.png)
![Screenshot](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/10-AI-ML-in-Cybersecurity/EmailSentry/screenshots/1.png)

## License

MIT

## Author

Author: mchyasn
