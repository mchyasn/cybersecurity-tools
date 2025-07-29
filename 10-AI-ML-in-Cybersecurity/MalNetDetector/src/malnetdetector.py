#!/usr/bin/env python3
import argparse, os, pandas as pd, joblib, logging, pefile
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import StandardScaler

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def extract_features(pe_path):
    try:
        pe = pefile.PE(pe_path)
        features = {
            "Size": os.path.getsize(pe_path),
            "NumImports": len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
            "NumSections": len(pe.sections),
            "EntropyMean": sum([s.get_entropy() for s in pe.sections]) / len(pe.sections),
        }
        return features
    except Exception as e:
        logging.warning(f"Skipping {pe_path}: {e}")
        return None

def train_model(input_csv, model_path):
    df = pd.read_csv(input_csv)
    X = df.drop(columns=['label'])
    y = df['label']
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    clf = LogisticRegression()
    clf.fit(X_scaled, y)
    preds = clf.predict(X_scaled)
    print(classification_report(y, preds))
    joblib.dump((scaler, clf), model_path)
    logging.info(f"Model saved to {model_path}")

def predict_file(pe_path, model_path):
    if not os.path.exists(pe_path):
        raise FileNotFoundError("PE file not found")
    scaler, clf = joblib.load(model_path)
    feats = extract_features(pe_path)
    if feats is None:
        return
    X = pd.DataFrame([feats])
    X_scaled = scaler.transform(X)
    prediction = clf.predict(X_scaled)[0]
    logging.info(f"Prediction for {pe_path}: {'Malicious' if prediction == 1 else 'Benign'}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MalNetDetector - Static PE Malware Classifier")
    parser.add_argument("--train", action="store_true", help="Train model using labeled CSV data")
    parser.add_argument("--predict", type=str, help="Predict a single PE file")
    parser.add_argument("--data", type=str, default="data/static_features.csv", help="Path to training CSV")
    parser.add_argument("--model", type=str, default="configs/malnet_model.pkl", help="Model path")
    args = parser.parse_args()
    try:
        if args.train:
            train_model(args.data, args.model)
        elif args.predict:
            predict_file(args.predict, args.model)
        else:
            parser.print_help()
    except Exception as e:
        logging.error(f"Error: {e}")
