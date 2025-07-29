#!/usr/bin/env python3
import argparse, os, pandas as pd, joblib, logging
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import numpy as np

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def train_detector(data_path, model_path):
    df = pd.read_csv(data_path)
    if 'label' in df.columns:
        df = df.drop(columns=['label'])
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df)
    detector = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    detector.fit(X_scaled)
    joblib.dump((scaler, detector), model_path)
    logging.info(f"ModelShield detector saved to {model_path}")

def score_input(input_path, model_path):
    scaler, detector = joblib.load(model_path)
    df = pd.read_csv(input_path)
    if 'label' in df.columns:
        df = df.drop(columns=['label'])
    X = scaler.transform(df)
    preds = detector.predict(X)
    for i, score in enumerate(preds):
        label = 'ADVERSARIAL' if score == -1 else 'CLEAN'
        logging.info(f"Sample {i+1}: {label}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ModelShield - Adversarial Input Detector")
    parser.add_argument("--train", action="store_true", help="Train adversarial detector from normal data CSV")
    parser.add_argument("--score", action="store_true", help="Score inputs for anomaly/adversarial presence")
    parser.add_argument("--input", type=str, help="CSV file of samples to score")
    parser.add_argument("--model", type=str, default="configs/modelshield.pkl", help="Model output or load path")
    parser.add_argument("--data", type=str, default="data/clean_train.csv", help="Training data path")
    args = parser.parse_args()

    try:
        if args.train:
            train_detector(args.data, args.model)
        elif args.score and args.input:
            score_input(args.input, args.model)
        else:
            parser.print_help()
    except Exception as e:
        logging.error(f"Error: {e}")
