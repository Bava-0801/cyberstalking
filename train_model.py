"""
TraceX Machine Learning Training Script
Trains a TF-IDF + Logistic Regression pipeline to classify messages into:
'safe', 'suspicious', 'cyberstalking'.
"""

import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "dataset.csv")
MODEL_DIR = os.path.join(BASE_DIR, "model")
MODEL_PATH = os.path.join(MODEL_DIR, "cyberstalking_model.pkl")


def train_model():
    print("=" * 60)
    print("TRACEX AI MODEL TRAINING PIPELINE")
    print("=" * 60)

    # 1. Load dataset
    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(f"Dataset not found at {DATASET_PATH}")

    df = pd.read_csv(DATASET_PATH)
    print(f"[*] Dataset loaded successfully from: {DATASET_PATH}")
    print(f"[*] Total dataset size: {len(df)} samples")
    print("\n[*] Class distribution:")
    print(df['label'].value_counts())

    X = df['message']
    y = df['label']

    # 2. Train/Test Split (75% train, 25% test with stratification)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.25,
        random_state=42,
        stratify=y
    )
    print(f"\n[*] Training set size: {len(X_train)} samples")
    print(f"[*] Testing set size: {len(X_test)} samples")

    # 3. Create Pipeline: TF-IDF (1,2 n-grams, lowercase) + Logistic Regression (balanced)
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2)
        )),
        ('clf', LogisticRegression(
            max_iter=1000,
            class_weight='balanced',
            random_state=42
        ))
    ])

    # 4. Train
    print("\n[*] Training TF-IDF + Logistic Regression pipeline...")
    pipeline.fit(X_train, y_train)

    # 5. Evaluate
    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n[*] Model Test Accuracy: {acc:.4f} ({acc * 100:.2f}%)")
    print("\n[*] Detailed Classification Report:")
    print(classification_report(y_test, y_pred))

    # 6. Save model artifact
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    print(f"[*] Model successfully saved to: {MODEL_PATH}")

    # Note model limitation reminder
    print("\n[!] IMPORTANT MODEL LIMITATION NOTICE:")
    print("    This is a proof-of-concept model trained on a small prototype dataset.")
    print("    Larger and more diverse datasets are required before production deployment.")
    print("=" * 60)

    return pipeline


if __name__ == "__main__":
    train_model()
