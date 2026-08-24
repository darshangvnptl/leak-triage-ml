"""
train.py
--------
Loads labelled data, extracts features, trains a gradient-boosted classifier.

Usage:
    python3 src/train.py --data data/synthetic/training_data.csv --model models/current/fp_classifier.joblib
"""

import argparse
import sys
import os

import pandas as pd
import joblib
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from features import extract_features, FEATURE_COLUMNS  # noqa: E402


def load_dataset(csv_path):
    df = pd.read_csv(csv_path)
    feature_rows = []
    for _, row in df.iterrows():
        feats = extract_features(
            secret=str(row["secret"]),
            file_path=str(row.get("file_path", "")),
            rule_id=str(row.get("rule_id", "")),
            match_context=str(row.get("match_context", "")),
        )
        feature_rows.append(feats)
    X = pd.DataFrame(feature_rows, columns=FEATURE_COLUMNS)
    y = df["label"].astype(int)
    return X, y


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="data/synthetic/training_data.csv")
    parser.add_argument("--model", default="models/current/fp_classifier.joblib")
    args = parser.parse_args()

    X, y = load_dataset(args.data)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)

    clf = HistGradientBoostingClassifier(max_iter=150, learning_rate=0.1, max_depth=4, random_state=42)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print("=== Classification report ===")
    print(classification_report(y_test, y_pred, target_names=["false_positive", "true_secret"]))
    print("=== Confusion matrix ===")
    print(confusion_matrix(y_test, y_pred))

    os.makedirs(os.path.dirname(args.model), exist_ok=True)
    joblib.dump({"model": clf, "feature_columns": FEATURE_COLUMNS}, args.model)
    print(f"Saved model to {args.model}")


if __name__ == "__main__":
    main()
