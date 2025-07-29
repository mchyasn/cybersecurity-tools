#!/usr/bin/env python3
import argparse, os, pandas as pd, joblib, logging
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def train_model(csv_path, model_path):
    if not os.path.exists(csv_path):
        raise FileNotFoundError("Training CSV file not found")
    df = pd.read_csv(csv_path)
    if 'text' not in df.columns or 'label' not in df.columns:
        raise ValueError("CSV must contain 'text' and 'label' columns")
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(max_features=3000)),
        ('clf', LogisticRegression(max_iter=1000))
    ])
    pipeline.fit(df['text'], df['label'])
    joblib.dump(pipeline, model_path)
    logging.info(f"Model trained and saved to {model_path}")

def predict_email(model_path, email_text):
    if not os.path.exists(model_path):
        raise FileNotFoundError("Trained model file not found")
    pipeline = joblib.load(model_path)
    pred = pipeline.predict([email_text])[0]
    result = 'Phishing' if pred == 1 else 'Benign'
    logging.info(f"Prediction: {result}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EmailSentry - Email Phishing Classifier")
    parser.add_argument("--train", action="store_true", help="Train the model from a CSV")
    parser.add_argument("--predict", type=str, help="Predict from given raw text or .txt file")
    parser.add_argument("--data", type=str, default="data/emails.csv", help="Path to training CSV")
    parser.add_argument("--model", type=str, default="configs/emailsentry_model.pkl", help="Model file path")
    args = parser.parse_args()
    try:
        if args.train:
            train_model(args.data, args.model)
        elif args.predict:
            if os.path.isfile(args.predict):
                with open(args.predict, "r") as f:
                    email_text = f.read()
            else:
                email_text = args.predict
            predict_email(args.model, email_text)
        else:
            parser.print_help()
    except Exception as e:
        logging.error(f"Error: {e}")
