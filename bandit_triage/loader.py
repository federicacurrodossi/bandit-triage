"""
Loads findings from Bandit's real JSON output format
(bandit -r . -f json -o results.json), or from our own hand-labeled
training data which uses the same schema plus an extra "label" field.
"""
import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class Finding:
    filename: str
    code: str
    issue_confidence: str
    issue_severity: str
    issue_text: str
    line_number: int
    test_id: str
    test_name: str
    cwe_id: Optional[int] = None
    cwe_link: Optional[str] = None
    label: Optional[str] = None  # only present in our labeled training data
    # Optional pre-extracted context for the taint engine. When present, the
    # engine reads these instead of opening the source file, so a dataset stays
    # self-contained and reproducible without the scanned projects on disk.
    function_code: Optional[str] = None  # the enclosing function's source
    sink_text: Optional[str] = None      # the flagged line, clean (no line no.)


# Bandit's own rule -> CWE mapping, used as a fallback when a finding carries no
# issue_cwe field (older Bandit versions, before the mapping was added, omit it,
# and some hand-written sample findings do too). Numbers match Bandit's plugins.
_RULE_CWE = {
    "B101": 703,   # assert_used
    "B105": 259,   # hardcoded_password_string
    "B106": 259,
    "B107": 259,
    "B301": 502,   # pickle
    "B602": 78,    # subprocess with shell=True
    "B603": 78,
    "B608": 89,    # hardcoded_sql_expressions
    "B614": 502,   # pytorch load
    "B615": 494,   # huggingface unsafe download
}


def _extract_cwe(item: dict):
    """Bandit's real JSON nests CWE info as issue_cwe: {id, link}. When that
    field is absent, fall back to the rule's known CWE so the reference still
    shows."""
    cwe = item.get("issue_cwe")
    if isinstance(cwe, dict) and cwe.get("id") is not None:
        return cwe.get("id"), cwe.get("link")
    rule_cwe = _RULE_CWE.get(item.get("test_id"))
    if rule_cwe is not None:
        return rule_cwe, f"https://cwe.mitre.org/data/definitions/{rule_cwe}.html"
    return None, None


def _build_finding(item: dict, with_label: bool) -> Finding:
    cwe_id, cwe_link = _extract_cwe(item)
    return Finding(
        filename=item["filename"],
        code=item.get("code", ""),
        issue_confidence=item.get("issue_confidence", "MEDIUM"),
        issue_severity=item.get("issue_severity", "MEDIUM"),
        issue_text=item.get("issue_text", ""),
        line_number=item.get("line_number", 0),
        test_id=item.get("test_id", ""),
        test_name=item.get("test_name", ""),
        cwe_id=cwe_id,
        cwe_link=cwe_link,
        label=item.get("label") if with_label else None,
        function_code=item.get("function_code"),
        sink_text=item.get("sink_text"),
    )


def load_bandit_report(path: str) -> List[Finding]:
    """Loads a real Bandit JSON report (has a top-level 'results' list)."""
    data = json.loads(Path(path).read_text())
    return [_build_finding(item, with_label=False)
            for item in data.get("results", [])]


def load_labeled_data(path: str) -> List[Finding]:
    """Loads our own hand-labeled training data (has a top-level 'findings'
    list, each entry additionally carrying a 'label')."""
    data = json.loads(Path(path).read_text())
    return [_build_finding(item, with_label=True)
            for item in data["findings"]]