#!/usr/bin/env python3
import argparse, os, pandas as pd, joblib, logging
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def load_data(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dataset not found: {path}")
    df = pd.read_csv(path)
    if 'url' not in df.columns or 'label' not in df.columns:
        raise ValueError("CSV must have 'url' and 'label' columns")
    return df['url'], df['label']

def train_model(data_path, model_path):
    urls, labels = load_data(data_path)
    x_train, x_test, y_train, y_test = train_test_split(urls, labels, test_size=0.2, random_state=42)
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(max_features=1000)),
        ('clf', LogisticRegression(solver='liblinear'))
    ])
    pipeline.fit(x_train, y_train)
    preds = pipeline.predict(x_test)
    logging.info("Training completed. Evaluation:")
    print(classification_report(y_test, preds))
    joblib.dump(pipeline, model_path)
    logging.info(f"Model saved to {model_path}")

def predict_url(url, model_path):
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Trained model not found: {model_path}")
    model = joblib.load(model_path)
    prediction = model.predict([url])[0]
    logging.info(f"Prediction for '{url}': {prediction}")
    return prediction

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PhishSniper - ML-based Phishing URL Detector")
    parser.add_argument("--train", action="store_true", help="Train model using CSV data")
    parser.add_argument("--predict", type=str, help="Predict if a URL is phishing or not")
    parser.add_argument("--data", type=str, default="data/mini_dataset.csv", help="Path to CSV data")
    parser.add_argument("--model", type=str, default="configs/phishsniper_model.pkl", help="Path to save/load model")
    args = parser.parse_args()

    try:
        if args.train:
            train_model(args.data, args.model)
        elif args.predict:
            predict_url(args.predict, args.model)
        else:
            parser.print_help()
    except Exception as e:
        logging.error(f"Error: {e}")
