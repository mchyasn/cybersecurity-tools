#!/usr/bin/env python3
import argparse, os, pandas as pd, joblib, logging
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def load_logs(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Log file not found: {file_path}")
    df = pd.read_csv(file_path)
    if 'message' not in df.columns:
        raise ValueError("CSV must contain a 'message' column")
    return df

def train_model(log_file, model_file):
    df = load_logs(log_file)
    vectorizer = TfidfVectorizer(max_features=1000)
    X = vectorizer.fit_transform(df['message'].astype(str))
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(X)
    joblib.dump((vectorizer, model), model_file)
    logging.info(f"Model saved to {model_file}")

def detect_anomalies(log_file, model_file):
    df = load_logs(log_file)
    vectorizer, model = joblib.load(model_file)
    X = vectorizer.transform(df['message'].astype(str))
    df['anomaly'] = model.predict(X)
    df['anomaly'] = df['anomaly'].map({1: 'normal', -1: 'anomaly'})
    print(df[df['anomaly'] == 'anomaly'])
    logging.info("Detection complete")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ThreatHawk - AI-based log anomaly detector")
    parser.add_argument("--train", action="store_true", help="Train model from CSV logs")
    parser.add_argument("--detect", action="store_true", help="Detect anomalies using trained model")
    parser.add_argument("--log", type=str, default="data/sample_logs.csv", help="Path to log CSV file")
    parser.add_argument("--model", type=str, default="configs/threathawk_model.pkl", help="Model file path")
    args = parser.parse_args()
    try:
        if args.train:
            train_model(args.log, args.model)
        elif args.detect:
            detect_anomalies(args.log, args.model)
        else:
            parser.print_help()
    except Exception as e:
        logging.error(f"Error: {e}")
