"""
generate_training_data.py
--------------------------
Synthetic labelled dataset: label=1 (real secret shapes, random values,
no real credentials) vs label=0 (common Gitleaks false positives).
"""

import csv
import random
import string
import uuid
import base64
import hashlib
import os

random.seed(42)
OUT_PATH = os.path.join(os.path.dirname(__file__), "training_data.csv")

FILE_POOL_REAL = [
    "config/production.env", "app/settings/prod.py",
    "infra/terraform/secrets.tfvars", "deploy/k8s/secret.yaml",
    ".github/workflows/deploy.yml", "backend/config.json",
]

FILE_POOL_FP = [
    "tests/fixtures/sample_config.env", "docs/examples/quickstart.md",
    "src/test/java/AuthTest.java", "__mocks__/apiClient.js",
    "package-lock.json", "README.md", "spec/support/fixtures.rb",
]

VAR_NAMES_REAL = ["AWS_SECRET_ACCESS_KEY", "DB_PASSWORD", "STRIPE_SECRET_KEY", "GITHUB_TOKEN", "API_KEY"]
VAR_NAMES_FP = ["EXAMPLE_API_KEY", "TEST_TOKEN", "DUMMY_SECRET", "integrity", "request_id", "session_id"]


def rand_alnum(n, alphabet=string.ascii_letters + string.digits):
    return "".join(random.choice(alphabet) for _ in range(n))


def rand_base64(n_bytes):
    return base64.b64encode(os.urandom(n_bytes)).decode()


TRUE_POSITIVE_GENERATORS = [
    ("aws-access-token", lambda: "AKIA" + rand_alnum(16, string.ascii_uppercase + string.digits)),
    ("github-pat", lambda: "ghp_" + rand_alnum(36)),
    ("stripe-live-key", lambda: "sk_live_" + rand_alnum(24)),
    ("generic-api-key", lambda: rand_alnum(random.randint(28, 40))),
]

FALSE_POSITIVE_GENERATORS = [
    ("generic-high-entropy-string", lambda: hashlib.sha1(rand_alnum(20).encode()).hexdigest()),
    ("generic-high-entropy-string", lambda: str(uuid.uuid4())),
    ("hex-string", lambda: "sha512-" + rand_base64(48)),
    ("generic-api-key", lambda: random.choice([
        "your_api_key_here", "changeme123", "example-secret-do-not-use",
    ])),
    ("generic-secret", lambda: " ".join(random.sample(
        ["lorem", "ipsum", "dolor", "sit", "amet", "consectetur"], 4))),
]


def build_row(secret, rule_id, is_real, var_name, file_path):
    return {
        "secret": secret,
        "file_path": file_path,
        "rule_id": rule_id,
        "match_context": f'{var_name} = "{secret}"',
        "label": 1 if is_real else 0,
    }


def generate(n_per_class=200):
    rows = []
    for _ in range(n_per_class):
        rule_id, fn = random.choice(TRUE_POSITIVE_GENERATORS)
        rows.append(build_row(fn(), rule_id, True, random.choice(VAR_NAMES_REAL), random.choice(FILE_POOL_REAL)))
    for _ in range(n_per_class):
        rule_id, fn = random.choice(FALSE_POSITIVE_GENERATORS)
        rows.append(build_row(fn(), rule_id, False, random.choice(VAR_NAMES_FP), random.choice(FILE_POOL_FP)))
    random.shuffle(rows)
    return rows


def main():
    rows = generate()
    with open(OUT_PATH, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["secret", "file_path", "rule_id", "match_context", "label"])
        writer.writeheader()
        writer.writerows(rows)
    n_pos = sum(r["label"] for r in rows)
    print(f"Wrote {len(rows)} rows ({n_pos} real, {len(rows)-n_pos} false positive) to {OUT_PATH}")


if __name__ == "__main__":
    main()
