"""
features.py
------------
Turns a Gitleaks finding into a numeric feature vector, using signals
Gitleaks itself doesn't use: entropy (which it does use, but as a single
global threshold rather than combined with everything else), string shape,
file/variable context, and readability.
"""

import math
import re
from collections import Counter

# ---------------------------------------------------------------------------
# Category 1: Entropy
# ---------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    """Average bits of 'surprise' per character. High = looks random/generated.
    Low = predictable/repetitive."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy = entropy + (-(probability * math.log2(probability)))
    return entropy


# ---------------------------------------------------------------------------
# Category 2: Shape (does the string match a known non-secret structure?)
# ---------------------------------------------------------------------------

def looks_hex(s: str) -> bool:
    if len(s) < 8:
        return False
    pattern = "[0-9a-fA-F]+"
    return re.fullmatch(pattern, s) is not None


def looks_uuid(s: str) -> bool:
    pattern = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    return re.fullmatch(pattern, s) is not None


def looks_base64(s: str) -> bool:
    if len(s) < 8:
        return False
    if len(s) % 4 != 0:
        return False
    pattern = "[A-Za-z0-9+/]+={0,2}"
    return re.fullmatch(pattern, s) is not None


# ---------------------------------------------------------------------------
# Category 3: Readability (does it contain real words, or look machine-generated?)
# ---------------------------------------------------------------------------

PLACEHOLDER_KEYWORDS = [
    "example", "sample", "dummy", "fake", "test", "xxx", "changeme",
    "your_api_key", "your-api-key", "placeholder", "redacted", "todo",
    "fixme", "lorem", "ipsum", "foobar",
]

COMMON_ENGLISH_WORDS = {
    "the", "and", "for", "are", "but", "not", "you", "your", "this", "that",
    "with", "have", "from", "they", "will", "would", "there", "their",
    "what", "about", "which", "when", "make", "like", "time", "just",
    "know", "take", "into", "year", "some", "could", "them", "than",
    "then", "now", "only", "come", "over", "think", "also", "back",
    "after", "use", "two", "how", "our", "work", "first", "well", "way",
    "even", "new", "want", "because", "any", "these", "give", "day",
    "most", "key", "secret", "token", "password", "config", "value",
    "data", "user", "name", "code", "file", "test", "sample", "example",
    "dummy", "fake", "here", "insert", "replace", "change", "please",
    "hello", "world", "request", "response", "session", "client", "server",
}

def has_dictionary_words(s: str) -> bool:
    """Rough heuristic: 3+ separate alphabetic runs of 3+ chars suggests
    human-typed words rather than one unbroken random blob."""
    runs = re.findall(r"[a-zA-Z]{3,}", s.lower())
    real_words = [w for w in runs if w in COMMON_ENGLISH_WORDS]
    return len(real_words) >= 1


def has_placeholder_keyword(s: str) -> bool:
    s_lower = s.lower()
    for keyword in PLACEHOLDER_KEYWORDS:
        if keyword in s_lower:
            return True
    return False


def char_class_ratios(s: str) -> dict:
    if not s:
        return {"ratio_upper": 0.0, "ratio_lower": 0.0, "ratio_digit": 0.0, "ratio_special": 0.0}
    length = len(s)
    upper = sum(1 for c in s if c.isupper())
    lower = sum(1 for c in s if c.islower())
    digit = sum(1 for c in s if c.isdigit())
    special = length - upper - lower - digit
    return {
        "ratio_upper": upper / length,
        "ratio_lower": lower / length,
        "ratio_digit": digit / length,
        "ratio_special": special / length,
    }


# ---------------------------------------------------------------------------
# Category 4: Context (where was this found?)
# ---------------------------------------------------------------------------

SENSITIVE_VAR_HINTS = [
    "secret", "token", "apikey", "api_key", "password", "pwd", "passwd",
    "access_key", "private_key", "auth", "credential", "bearer",
]

TEST_PATH_HINTS = [
    "/test/", "/tests/", "/spec/", "/mock", "/fixture", "/example",
    "/sample", "/docs/", ".test.", ".spec.", "_test.", "_spec.",
]

RISKY_FILE_EXTENSIONS = [".env", ".pem", ".key", ".yml", ".yaml", ".json", ".sh", ".tf", ".conf", ".ini"]
LOW_RISK_FILE_EXTENSIONS = [".md", ".txt", ".rst"]


def _contains_any(haystack: str, needles) -> bool:
    haystack = haystack.lower()
    for n in needles:
        if n in haystack:
            return True
    return False


def context_features(file_path: str, match_context: str, rule_id: str) -> dict:
    file_path = file_path or ""
    match_context = match_context or ""
    rule_id = rule_id or ""
    ext = ""
    if "." in file_path:
        ext = "." + file_path.rsplit(".", 1)[-1]

    return {
        "ctx_has_sensitive_var": int(_contains_any(match_context, SENSITIVE_VAR_HINTS)),
        "file_is_test_path": int(_contains_any(file_path, TEST_PATH_HINTS)),
        "file_is_risky_ext": int(ext.lower() in RISKY_FILE_EXTENSIONS),
        "file_is_lowrisk_ext": int(ext.lower() in LOW_RISK_FILE_EXTENSIONS),
        "rule_is_generic": int(_contains_any(rule_id, ["generic", "high-entropy"])),
    }


# ---------------------------------------------------------------------------
# Public entry point — combines all four categories into one feature row
# ---------------------------------------------------------------------------

FEATURE_COLUMNS = [
    "entropy", "length", "ratio_upper", "ratio_lower", "ratio_digit", "ratio_special",
    "looks_hex", "looks_uuid", "looks_base64",
    "has_dictionary_words", "has_placeholder_keyword",
    "ctx_has_sensitive_var", "file_is_test_path", "file_is_risky_ext",
    "file_is_lowrisk_ext", "rule_is_generic",
]


def extract_features(secret: str, file_path: str = "", rule_id: str = "", match_context: str = "") -> dict:
    secret = secret or ""
    feats = {}
    feats["entropy"] = shannon_entropy(secret)
    feats["length"] = len(secret)
    feats.update(char_class_ratios(secret))
    feats["looks_hex"] = int(looks_hex(secret))
    feats["looks_uuid"] = int(looks_uuid(secret))
    feats["looks_base64"] = int(looks_base64(secret))
    feats["has_dictionary_words"] = int(has_dictionary_words(secret))
    feats["has_placeholder_keyword"] = int(has_placeholder_keyword(secret))
    feats.update(context_features(file_path, match_context or secret, rule_id))
    return {col: feats.get(col, 0) for col in FEATURE_COLUMNS}