"""
Turns a Bandit Finding into a numeric feature vector.

The features are deliberately simple and inspectable -- each one is a
concrete, explainable signal a human reviewer would actually look for when
manually triaging a Bandit finding (is this in a test file? does the value
look like a real secret or a placeholder? does tainted input reach this
call?), not an opaque learned representation.
"""
import ast
import re

import numpy as np

from .loader import Finding
from .taint import (
    analyze,
    enclosing_function,
    sink_line,
    RuleConfig,
)

# Per-rule engine configuration. Only injection rules with a config get the
# taint engine; today that is B608 (SQL). Adding B602/B703/... here later gives
# them the same treatment without touching the feature code.
_RULE_CONFIGS = {
    "B608": RuleConfig(
        rule_id="B608",
        sink_names={"execute", "executemany", "executescript", "raw"},
        sanitizers={"quote_name", "quote", "escape", "escape_string", "int"},
    ),
}


def taint_signals(finding: Finding) -> tuple:
    """Return (has_tainted_input, has_sanitizer) for a finding.

    When the finding's rule has an engine config and the enclosing function can
    be recovered from the source file, the values come from the taint engine,
    which follows each value back to its origin. When the function is not
    available (source file missing) or the rule has no config, it falls back to
    the tainted-input regex and reports no sanitizer information.
    """
    config = _RULE_CONFIGS.get(finding.test_id)
    if config is not None:
        # Prefer context baked into the dataset; fall back to reading the file.
        func = finding.function_code or enclosing_function(
            finding.filename, finding.line_number)
        if func is not None:
            sink = (finding.sink_text
                    or sink_line(finding.filename, finding.line_number)
                    or finding.code)
            result = analyze(func, sink, config)
            # Trust the engine when it reached a definite conclusion: it either
            # traced an untrusted source, or completed without hitting anything
            # it could not follow.
            if result.is_tainted or result.analysis_complete:
                return (1.0 if result.is_tainted else 0.0,
                        1.0 if result.has_sanitizer else 0.0)
    # Fallback: the original regex, with no sanitizer information.
    has_tainted = 1.0 if TAINTED_INPUT_RE.search(finding.code) else 0.0
    return has_tainted, 0.0

DUMMY_KEYWORDS = re.compile(
    r"(test|dummy|example|fake|changeme|demo|placeholder|sample|xxx|todo)",
    re.IGNORECASE,
)
# an empty / null / missing flagged value is not a real secret: a config
# default like SECRET_KEY: None has the shape of a secret (suspicious name,
# production code) but no actual value. \b matches whole words only, so this
# won't fire on real secrets that merely contain "none" (e.g. "none_of_it_42").
EMPTY_VALUE_RE = re.compile(r"^(none|null|nil|)$", re.IGNORECASE)
TAINTED_INPUT_RE = re.compile(
    # web / CLI / environment input
    r"(request\.|input\(|sys\.argv|os\.environ\[|form\[|args\.get|"
    r"uploaded_file|user_upload|download_url|repo_id\s*=\s*request|"
    # external cache stores (redis / memcached): data another process can write
    r"redis|memcache|cache\.get\(|\.hget\(|\.lpop\(|\.rpop\(|"
    # raw network sockets
    r"socket\.|\.recv\(|\.recvfrom\(|"
    # message queues / brokers (kafka, rabbitmq/pika, celery, sqs)
    r"\.consume\(|\.poll\(|basic_get|kafka|pika\.|sqs)",
    re.IGNORECASE,
)
# crude but useful: a "+" or f-string/format concatenation involving a
# variable (not a fully static string) right around the flagged call
DYNAMIC_CONCAT_RE = re.compile(r'(\+\s*\w+|f"[^"]*\{|\.format\()')

KNOWN_TEST_IDS = ["B101", "B105", "B608"]

FEATURE_NAMES = [
    "confidence",
    "severity",
    "is_test_file",
    "has_dummy_keyword",
    "has_tainted_input",
    "has_sanitizer",
    "has_dynamic_concat",
    "secret_score",
] + [f"rule_{tid}" for tid in KNOWN_TEST_IDS]

_LEVEL_MAP = {"LOW": 0.0, "MEDIUM": 0.5, "HIGH": 1.0, "UNDEFINED": 0.5}

# matches the value Bandit quotes in issue_text, e.g.
#   Possible hardcoded password: 'd6s$f9g!j8mg7hw?n&2'
QUOTED_VALUE_RE = re.compile(r"[:\s]'([^']*)'|[:\s]\"([^\"]*)\"")


def extract_flagged_value(finding: Finding) -> str:
    """
    Pull the actual string Bandit flagged out of issue_text. For a B105 the
    text looks like: Possible hardcoded password: 'the_value'. Returns the
    value, or an empty string if none is found.
    """
    match = QUOTED_VALUE_RE.search(finding.issue_text)
    if not match:
        return ""
    # one of the two capture groups (single- or double-quoted) will be set
    return match.group(1) if match.group(1) is not None else (match.group(2) or "")


def secret_score(value: str) -> float:
    """
    A gradual 0..1 score of how much a string looks like a real secret,
    rather than a placeholder. Combines two simple, explainable signals,
    averaged:

      1. Length  -- real secrets tend to be long; 'root' or '1234' are short.
      2. Character variety -- real secrets mix lowercase, uppercase, digits,
         and symbols; placeholders like 'blerg' use just one kind.

    This is intentionally imperfect: a real secret could be short, and a
    placeholder could be long. It just gives the model one more useful clue
    it doesn't have today. A future version could add a dictionary-word check
    (e.g. 'secret', 'password' are real words, so likely placeholders).
    """
    if not value:
        return 0.0

    # signal 1: length, normalized so ~16+ chars scores near 1.0
    length_score = min(len(value) / 16.0, 1.0)

    # signal 2: character variety (how many of the 4 classes are present)
    classes_present = 0
    if re.search(r"[a-z]", value):
        classes_present += 1
    if re.search(r"[A-Z]", value):
        classes_present += 1
    if re.search(r"[0-9]", value):
        classes_present += 1
    if re.search(r"[^a-zA-Z0-9]", value):  # any symbol
        classes_present += 1
    variety_score = classes_present / 4.0

    return (length_score + variety_score) / 2.0


def _has_test_content(source: str) -> bool:
    """True when a file's content shows it actually contains tests: a class that
    inherits from a *TestCase base (unittest.TestCase, Django's SimpleTestCase,
    TransactionTestCase, and so on).

    This is the reliable signal in practice. A bare def test_* is not enough on
    its own: production framework code contains functions and methods that begin
    with test_ without being tests (Django's own test/runner.py has a
    test_match_tags helper and a RemoteTestResult.test_index method, neither a
    test). Requiring a TestCase base class separates a real test file, where an
    assert is routine so a Bandit B101 is usually a false positive, from
    production code that merely lives under a path containing "test", such as
    Django's django/test/ package, which provides testing tools but is not a
    test file itself.

    The trade-off is explicit: a project written purely in pytest style (module
    level def test_* with no TestCase class) would not be recognized by content.
    The path based fallback below still catches those by their test_*.py or
    tests/ naming, and the datasets this was measured on contain no such case.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                name = base.attr if isinstance(base, ast.Attribute) else (
                    base.id if isinstance(base, ast.Name) else "")
                if name.endswith("TestCase"):
                    return True
    return False


# Path-based test conventions, used together with content: a tests/ directory
# (plural only, so Django's singular django/test/ production package does not
# match), or a test_*.py / *_test.py / tests.py / conftest.py filename.
_TEST_PATH_RE = re.compile(
    r"(^|/)tests/|(^|/)(test_[^/]*|[^/]*_test|tests|conftest)\.py$",
    re.IGNORECASE,
)


def is_test_file(finding: Finding) -> float:
    """Whether the finding sits in a test file or test support code.

    Two signals are combined, because "test file" has two faces. Content: a file
    that defines a *TestCase class is a test file wherever it lives. Path: a file
    under a tests/ directory (plural) or named test_*.py / *_test.py is part of a
    test suite even when it holds no TestCase itself (models.py, urls.py and
    tasks.py under tests/ are support code the tests import, where an assert is
    still test code and a Bandit B101 is still a false positive).

    A file counts as a test file if either signal fires. The path signal is
    deliberately the plural tests/ (or a test_* filename), not the singular
    test/, so Django's django/test/ production package, which contains no
    TestCase classes and is not under a tests/ directory, is correctly left out.
    """
    by_path = 1.0 if _TEST_PATH_RE.search(finding.filename) else 0.0
    by_content = 0.0
    try:
        with open(finding.filename, "r", encoding="utf-8") as fh:
            by_content = 1.0 if _has_test_content(fh.read()) else 0.0
    except (OSError, UnicodeDecodeError):
        by_content = 0.0
    return 1.0 if (by_path or by_content) else 0.0


def extract_features(finding: Finding) -> np.ndarray:
    confidence = _LEVEL_MAP.get(finding.issue_confidence.upper(), 0.5)
    severity = _LEVEL_MAP.get(finding.issue_severity.upper(), 0.5)

    test_file = is_test_file(finding)
    value = extract_flagged_value(finding)
    value_secret_score = secret_score(value)

    # a finding counts as "dummy" if the code contains a placeholder keyword
    # OR the flagged value itself is empty/null (None, "", null) -- both mean
    # "not a real secret".
    has_dummy = 1.0 if (DUMMY_KEYWORDS.search(finding.code)
                        or EMPTY_VALUE_RE.match(value.strip())) else 0.0
    has_tainted, has_sanitizer = taint_signals(finding)
    has_dynamic = 1.0 if DYNAMIC_CONCAT_RE.search(finding.code) else 0.0

    rule_flags = [1.0 if finding.test_id == tid else 0.0 for tid in KNOWN_TEST_IDS]

    vector = [
        confidence,
        severity,
        test_file,
        has_dummy,
        has_tainted,
        has_sanitizer,
        has_dynamic,
        value_secret_score,
    ] + rule_flags
    return np.array(vector, dtype=float)