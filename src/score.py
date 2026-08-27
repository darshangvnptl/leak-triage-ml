"""
score.py
--------
Scores a real Gitleaks JSON report using the trained classifier.

Usage:
    python3 src/score.py --report examples/sample_gitleaks_report.json \
        --model models/current/fp_classifier.joblib --out scored-report.json
"""

import argparse
import json
import sys
import os

import joblib
import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))
from features import extract_features  # noqa: E402


def load_gitleaks_report(path):
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, dict) and "findings" in data:
        return data["findings"]
    return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True)
    parser.add_argument("--model", default="models/current/fp_classifier.joblib")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--out", default="scored-report.json")
    args = parser.parse_args()

    findings = load_gitleaks_report(args.report)
    bundle = joblib.load(args.model)
    model, feature_columns = bundle["model"], bundle["feature_columns"]

    feature_rows = []
    for f in findings:
        feature_rows.append(extract_features(
            secret=f.get("Secret", ""),
            file_path=f.get("File", ""),
            rule_id=f.get("RuleID", ""),
            match_context=f.get("Match", ""),
        ))
    X = pd.DataFrame(feature_rows, columns=feature_columns)
    probs = model.predict_proba(X)[:, 1]

    enriched = []
    for finding, prob in zip(findings, probs):
        f = dict(finding)
        f["ml_probability"] = round(float(prob), 4)
        f["ml_verdict"] = "likely_secret" if prob >= args.threshold else "likely_false_positive"
        enriched.append(f)
    enriched.sort(key=lambda f: f["ml_probability"], reverse=True)

    with open(args.out, "w") as f:
        json.dump(enriched, f, indent=2)

    n_secret = sum(1 for f in enriched if f["ml_verdict"] == "likely_secret")
    print(f"Scored {len(enriched)} findings -> {args.out}")
    print(f"  likely_secret: {n_secret}, likely_false_positive: {len(enriched) - n_secret}")
    for f in enriched:
        if f["ml_verdict"] == "likely_secret":
            print(f"  [{f['ml_probability']:.2f}] {f.get('RuleID')} {f.get('File')}:{f.get('StartLine')}")

    sys.exit(1 if n_secret > 0 else 0)


if __name__ == "__main__":
    main()
