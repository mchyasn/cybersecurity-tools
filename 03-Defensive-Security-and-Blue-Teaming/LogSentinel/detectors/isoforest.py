import os
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

class Detector:
    def __init__(self, contamination=0.1):
        self.model_path = "models/isoforest.pkl"
        self.model = None
        self.contamination = contamination
        self._load_or_init_model()

    def _load_or_init_model(self):
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
        else:
            self.model = IsolationForest(n_estimators=100, contamination=self.contamination, random_state=42)

    def fit(self, df):
        X = self._prepare_features(df)
        self.model.fit(X)
        joblib.dump(self.model, self.model_path)

    def predict(self, df):
        X = self._prepare_features(df)
        if not hasattr(self.model, "estimators_"):
            self.fit(df)
        return self.model.predict(X)

    def _prepare_features(self, df):
        feature_cols = ["length", "digit_count", "upper_count", "timestamp_epoch"]
        return df[feature_cols].fillna(0.0)
