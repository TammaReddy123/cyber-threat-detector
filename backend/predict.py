import os
import numpy as np
from joblib import load
from feature_extraction import extract_url_features
import pandas as pd


# Get the project root directory (parent of backend directory)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))

# Try to find models in backend directory first (for deployment), then in project root
if os.path.exists(os.path.join(BACKEND_DIR, "url_rf_model.joblib")):
    MODEL_PATH = os.path.join(BACKEND_DIR, "url_rf_model.joblib")
    LABEL_ENCODER_PATH = os.path.join(BACKEND_DIR, "label_encoder.joblib")
else:
    MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "url_rf_model.joblib")
    LABEL_ENCODER_PATH = os.path.join(PROJECT_ROOT, "models", "label_encoder.joblib")

PROCESSED_DATA_PATH = os.path.join(PROJECT_ROOT, "data", "processed", "urls_features.csv")

# Debug prints for troubleshooting (can be removed in production)
# print(f"Model path: {MODEL_PATH}")
# print(f"Model exists: {os.path.exists(MODEL_PATH)}")
# print(f"Label encoder exists: {os.path.exists(LABEL_ENCODER_PATH)}")
# print(f"Processed data exists: {os.path.exists(PROCESSED_DATA_PATH)}")


class URLThreatModel:
    def __init__(self):
        self.model_available = False
        if os.path.exists(MODEL_PATH) and os.path.exists(LABEL_ENCODER_PATH):
            try:
                self.model = load(MODEL_PATH)
                self.label_encoder = load(LABEL_ENCODER_PATH)
                self.model_available = True
                print("ML model loaded successfully")

                # Load expected features once
                if os.path.exists(PROCESSED_DATA_PATH):
                    features_df = pd.read_csv(PROCESSED_DATA_PATH)
                    self.expected_features = features_df.drop(columns=["url", "label"]).columns.tolist()
                else:
                    self.expected_features = []
            except Exception as e:
                print(f"Failed to load ML model: {e}")
                self.model_available = False
        else:
            print("ML model files not found. Using fallback prediction.")
            self.model_available = False

    def predict_single(self, url: str):
        if not self.model_available:
            # Fallback prediction based on simple heuristics
            return self._fallback_prediction(url)

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

    def _fallback_prediction(self, url: str):
        """Fallback prediction when ML model is not available"""
        # Simple heuristic-based prediction
        suspicious_keywords = ['login', 'password', 'bank', 'paypal', 'bitcoin', 'crypto', 'free', 'win', 'prize']
        url_lower = url.lower()

        # Check for suspicious patterns
        is_suspicious = any(keyword in url_lower for keyword in suspicious_keywords)

        if is_suspicious:
            prediction = "phishingCredential"
            confidence = 0.7
            label_probs = {
                "benign": 0.2,
                "phishingCredential": 0.7,
                "malwareSite": 0.05,
                "adFraud": 0.03,
                "financialScam": 0.02
            }
        else:
            prediction = "benign"
            confidence = 0.6
            label_probs = {
                "benign": 0.6,
                "phishingCredential": 0.2,
                "malwareSite": 0.1,
                "adFraud": 0.05,
                "financialScam": 0.05
            }

        return prediction, confidence, label_probs
