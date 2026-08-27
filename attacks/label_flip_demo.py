"""
label_flip_demo.py
-------------------
Demonstrates a training-data poisoning (label-flipping) attack against the
Phase 1 classifier.

Attack narrative:
  1. Train a clean baseline model. Show it correctly flags a target secret
     as likely_secret with high confidence.
  2. Simulate an attacker who, during normal triage, mislabels several REAL
     secrets that share the target's feature profile as false positives.
     (They never touch the target itself - only similar-looking training
     examples.)
  3. Retrain on the poisoned data.
  4. Show the exact same target secret now scores as likely_false_positive -
     the model was never attacked directly, its training data was.

Fully deterministic (uses threadpool_limits, same as src/train.py) so this
is safe to run live on stage without flaky results.

Usage:
    python3 attacks/label_flip_demo.py
"""

import sys
import os
import copy

import pandas as pd
import numpy as np
import threadpoolctl
from sklearn.ensemble import HistGradientBoostingClassifier

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from features import extract_features, FEATURE_COLUMNS  # noqa: E402

DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "synthetic", "training_data.csv")
RESULTS_PATH = os.path.join(os.path.dirname(__file__), "label_flip_results.csv")

# Fixed target secret - hardcoded, not randomly generated, so the demo is
# identical every single run. This is the secret the attacker wants to sneak
# past the model.
TARGET_SECRET = "sk_live_ZQwneTx4RfmvV5tG9YbW3sPq"
TARGET_FILE = "app/settings/prod.py"
TARGET_RULE = "stripe-live-key"
TARGET_MATCH = f'STRIPE_SECRET_KEY = "{TARGET_SECRET}"'


def load_features_and_labels(df):
    rows = [
        extract_features(r["secret"], r["file_path"], r["rule_id"], r["match_context"])
        for _, r in df.iterrows()
    ]
    X = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    y = df["label"].astype(int).reset_index(drop=True)
    return X, y


def train_model(X, y):
    clf = HistGradientBoostingClassifier(max_iter=150, learning_rate=0.1, max_depth=4, random_state=42)
    with threadpoolctl.threadpool_limits(limits=1):
        clf.fit(X, y)
    return clf


def score_target(model):
    feats = extract_features(TARGET_SECRET, TARGET_FILE, TARGET_RULE, TARGET_MATCH)
    X = pd.DataFrame([feats], columns=FEATURE_COLUMNS)
    return float(model.predict_proba(X)[:, 1][0])


def find_nearest_real_secrets(df, X, k):
    """Find the k real secrets (label=1) in the training set whose feature
    vectors are closest to the target - these are what the attacker would
    poison, since they're the examples most likely to shift the model's
    decision boundary in the target's region."""
    target_feats = extract_features(TARGET_SECRET, TARGET_FILE, TARGET_RULE, TARGET_MATCH)
    target_row = pd.DataFrame([target_feats], columns=FEATURE_COLUMNS).astype(float)

    X_float = X.astype(float)
    X_norm = (X_float - X_float.min()) / (X_float.max() - X_float.min() + 1e-9)
    target_norm = (target_row - X_float.min()) / (X_float.max() - X_float.min() + 1e-9)

    dists = np.sqrt(((X_norm - target_norm.values[0]) ** 2).sum(axis=1))
    real_secret_idx = df.index[df["label"] == 1].tolist()
    real_dists = dists.loc[real_secret_idx].sort_values()
    return real_dists.index[:k].tolist()


def run_sweep(df, poison_counts):
    """Retrain at increasing levels of poisoning, recording the target's
    probability at each step - this produces the before/after curve for
    the demo's chart."""
    results = []
    X_all, y_all = load_features_and_labels(df)

    for k in poison_counts:
        poisoned_df = df.copy()
        if k > 0:
            nearest_idx = find_nearest_real_secrets(df, X_all, k)
            poisoned_df.loc[nearest_idx, "label"] = 0

        X, y = load_features_and_labels(poisoned_df)
        model = train_model(X, y)
        prob = score_target(model)
        results.append({"poisoned_labels": k, "target_probability": prob})
        verdict = "likely_secret" if prob >= 0.5 else "likely_false_positive"
        print(f"  poisoned_labels={k:3d}   target_probability={prob:.4f}   verdict={verdict}")

    return pd.DataFrame(results)


def main():
    print("=" * 70)
    print("LABEL FLIPPING ATTACK DEMO")
    print("=" * 70)
    print(f"\nTarget secret : {TARGET_SECRET}")
    print(f"File          : {TARGET_FILE}")
    print(f"Rule          : {TARGET_RULE}\n")

    df = pd.read_csv(DATA_PATH)

    print("--- Step 1: Baseline (clean training data) ---")
    X, y = load_features_and_labels(df)
    baseline_model = train_model(X, y)
    baseline_prob = score_target(baseline_model)
    baseline_verdict = "likely_secret" if baseline_prob >= 0.5 else "likely_false_positive"
    print(f"  Baseline target_probability = {baseline_prob:.4f}  ->  {baseline_verdict}\n")

    print("--- Step 2: Poisoning sweep ---")
    print("  (flipping labels on real secrets nearest to the target's feature vector)")
    sweep_counts = [0, 2, 4, 6, 8, 10, 14, 18]
    results_df = run_sweep(df, sweep_counts)

    print("\n--- Step 3: Summary ---")
    final_prob = results_df.iloc[-1]["target_probability"]
    print(f"  Before attack : {baseline_prob:.4f}  (likely_secret)")
    print(f"  After attack  : {final_prob:.4f}  ({'likely_secret' if final_prob >= 0.5 else 'likely_false_positive'})")
    print(f"  Labels poisoned to flip the verdict: as few as "
          f"{results_df[results_df['target_probability'] < 0.5]['poisoned_labels'].min()} "
          f"out of {len(df)} training rows")

    results_df.to_csv(RESULTS_PATH, index=False)
    print(f"\nSweep results saved to {RESULTS_PATH}")


if __name__ == "__main__":
    main()