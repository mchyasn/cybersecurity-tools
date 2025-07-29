# MalNetDetector

## Description
MalNetDetector is a static malware classification tool that uses features extracted from Windows PE (Portable Executable) files to determine whether a file is malicious or benign. It leverages basic static attributes like file size, number of imported functions, section entropy, and more, and trains a Logistic Regression model to classify samples. This tool is built for use in malware triage, incident response, and endpoint telemetry analysis.

## Features
- Static feature extraction from PE files using `pefile`
- Logistic Regression model with scikit-learn
- CSV-based training dataset
- Predicts on individual `.exe` files
- Saves trained model via `joblib`
- CLI-based interaction with `argparse`

## Installation
```bash
git clone https://github.com/mchyasn/cybersecurity-tools.git
cd 10-AI-ML-in-Cybersecurity/MalNetDetector
python3 -m venv venv
source venv/bin/activate
pip install pandas scikit-learn joblib pefile
````

## Usage

### Train the model:

```bash
python3 src/malnetdetector.py --train
```

### Predict a single file:

```bash
python3 src/malnetdetector.py --predict /path/to/file.exe
```

### Help:

```bash
python3 src/malnetdetector.py --help
```

## Screenshots

![Screenshot](https://raw.githubusercontent.com/mchyasn/cybersecurity-tools/main/10-AI-ML-in-Cybersecurity/MalNetDetector/screenshots/0.png)

## License

MIT

## Author

Author: mchyasn

```
```
