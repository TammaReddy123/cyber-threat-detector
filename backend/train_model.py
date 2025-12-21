import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from joblib import dump

from feature_extraction import extract_features_from_dataframe

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DATA_PATH = os.path.join(BASE_DIR, "data", "raw", "urls_labeled.csv")
PROCESSED_DATA_PATH = os.path.join(BASE_DIR, "data", "processed", "urls_features.csv")
MODEL_PATH = os.path.join(BASE_DIR, "models", "url_rf_model.joblib")
LABEL_ENCODER_PATH = os.path.join(BASE_DIR, "models", "label_encoder.joblib")

# ⛔ Labels below 2 samples get removed to prevent stratify errors
MIN_SAMPLES_PER_CLASS = 2


def load_raw_data() -> pd.DataFrame:
    if not os.path.exists(RAW_DATA_PATH):
        raise FileNotFoundError(f"Dataset not found at {RAW_DATA_PATH}")

    try:
        df = pd.read_csv(RAW_DATA_PATH, encoding="utf-8")
    except Exception:
        df = pd.read_csv(RAW_DATA_PATH, encoding="latin1", on_bad_lines="skip")

    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("Dataset must contain 'url' and 'label' columns.")

    df = df[["url", "label"]].dropna().drop_duplicates()

    # Remove classes with too few samples
    class_counts = df["label"].value_counts()
    valid_classes = class_counts[class_counts >= MIN_SAMPLES_PER_CLASS].index
    df = df[df["label"].isin(valid_classes)]

    return df


def train_model():
    print("[*] Loading data...")
    df = load_raw_data()

    print(f"[*] Dataset size: {len(df)} rows")
    print("[!] Label distribution:")
    print(df["label"].value_counts())

    print("[*] Extracting features...")
    features_df = extract_features_from_dataframe(df)

    os.makedirs(os.path.dirname(PROCESSED_DATA_PATH), exist_ok=True)
    features_df.to_csv(PROCESSED_DATA_PATH, index=False)

    # Separate X and y
    X = features_df.drop(columns=["url", "label"])
    y = features_df["label"]

    # Encode labels
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    # Decide if stratify can be used
    if pd.Series(y_encoded).value_counts().min() < 2:
        stratify = None
        print("[!] Stratify disabled because some classes are too small.")
    else:
        stratify = y_encoded

    print("[*] Splitting train/test...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=stratify
    )

    print("[*] Training RandomForestClassifier...")
    clf = RandomForestClassifier(
        n_estimators=350,
        max_depth=None,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced"
    )
    clf.fit(X_train, y_train)

    print("[*] Evaluating model on test set...")
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    # Save model and encoder
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    dump(clf, MODEL_PATH)
    dump(le, LABEL_ENCODER_PATH)

    print(f"✔ Model saved to: {MODEL_PATH}")
    print(f"✔ Label encoder saved to: {LABEL_ENCODER_PATH}")
    print("🎉 Training Completed Successfully!")


if __name__ == "__main__":
    train_model()
