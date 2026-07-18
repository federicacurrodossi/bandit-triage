"""
Turns a Bandit Finding into a numeric feature vector.

The features are deliberately simple and inspectable -- each one is a
concrete, explainable signal a human reviewer would actually look for when
manually triaging a Bandit finding (is this in a test file? does the value
look like a real secret or a placeholder? does tainted input reach this
call?), not an opaque learned representation.
"""
import re

import numpy as np

from .loader import Finding

DUMMY_KEYWORDS = re.compile(
    r"(test|dummy|example|fake|changeme|demo|placeholder|sample|xxx|todo)",
    re.IGNORECASE,
)
TAINTED_INPUT_RE = re.compile(
    r"(request\.|input\(|sys\.argv|os\.environ\[|form\[|args\.get|"
    r"uploaded_file|user_upload|download_url|repo_id\s*=\s*request)",
    re.IGNORECASE,
)
# crude but useful: a "+" or f-string/format concatenation involving a
# variable (not a fully static string) right around the flagged call
DYNAMIC_CONCAT_RE = re.compile(r'(\+\s*\w+|f"[^"]*\{|\.format\()')

KNOWN_TEST_IDS = ["B105", "B101", "B602", "B301", "B608", "B614", "B615"]

FEATURE_NAMES = [
    "confidence",
    "severity",
    "is_test_file",
    "has_dummy_keyword",
    "has_tainted_input",
    "has_dynamic_concat",
] + [f"rule_{tid}" for tid in KNOWN_TEST_IDS]

_LEVEL_MAP = {"LOW": 0.0, "MEDIUM": 0.5, "HIGH": 1.0, "UNDEFINED": 0.5}


def extract_features(finding: Finding) -> np.ndarray:
    confidence = _LEVEL_MAP.get(finding.issue_confidence.upper(), 0.5)
    severity = _LEVEL_MAP.get(finding.issue_severity.upper(), 0.5)

    is_test_file = 1.0 if re.search(r"test", finding.filename, re.IGNORECASE) else 0.0
    has_dummy = 1.0 if DUMMY_KEYWORDS.search(finding.code) else 0.0
    has_tainted = 1.0 if TAINTED_INPUT_RE.search(finding.code) else 0.0
    has_dynamic = 1.0 if DYNAMIC_CONCAT_RE.search(finding.code) else 0.0

    rule_flags = [1.0 if finding.test_id == tid else 0.0 for tid in KNOWN_TEST_IDS]

    vector = [confidence, severity, is_test_file, has_dummy, has_tainted, has_dynamic] + rule_flags
    return np.array(vector, dtype=float)
