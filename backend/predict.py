import os
import numpy as np
from joblib import load
from feature_extraction import extract_url_features
import pandas as pd


# Get the project root directory (parent of backend directory)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "url_rf_model.joblib")
LABEL_ENCODER_PATH = os.path.join(PROJECT_ROOT, "models", "label_encoder.joblib")
PROCESSED_DATA_PATH = os.path.join(PROJECT_ROOT, "data", "processed", "urls_features.csv")

print(f"Looking for models in: {PROJECT_ROOT}/models/")
print(f"Model path: {MODEL_PATH}")
print(f"Label encoder path: {LABEL_ENCODER_PATH}")


class URLThreatModel:
    def __init__(self):
        if not os.path.exists(MODEL_PATH) or not os.path.exists(LABEL_ENCODER_PATH):
            raise FileNotFoundError("Model or label encoder not found. Train the model first.")

        self.model = load(MODEL_PATH)
        self.label_encoder = load(LABEL_ENCODER_PATH)

        # Load expected features once
        if os.path.exists(PROCESSED_DATA_PATH):
            features_df = pd.read_csv(PROCESSED_DATA_PATH)
            self.expected_features = features_df.drop(columns=["url", "label"]).columns.tolist()
        else:
            self.expected_features = []

    def predict_single(self, url: str):
        feats = extract_url_features(url)
        df = pd.DataFrame([feats])

        # Load expected features from processed data
        features_df = pd.read_csv(PROCESSED_DATA_PATH)
        expected_features = features_df.drop(columns=["url", "label"]).columns.tolist()

        # Fill missing features with 0
        for col in expected_features:
            if col not in df.columns:
                df[col] = 0

        X = df[expected_features]
        probs = self.model.predict_proba(X)[0]
        idx = int(np.argmax(probs))
        predicted_label = self.label_encoder.inverse_transform([idx])[0]
        confidence = float(probs[idx])

        # Return full probability map
        label_probs = {
            self.label_encoder.inverse_transform([i])[0]: float(p)
            for i, p in enumerate(probs)
        }

        return predicted_label, confidence, label_probs
