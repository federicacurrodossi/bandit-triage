"""
CLI entry point.

    python3 -m bandit_triage.cli triage bandit_results.json --model model.json

Where bandit_results.json comes from running real Bandit yourself:
    bandit -r . -f json -o bandit_results.json
"""
import argparse
import sys
from pathlib import Path

from .classifier import TriageClassifier
from .features import extract_features
from .loader import load_bandit_report


FEATURE_DESCRIPTIONS = {
    "confidence": "Bandit's own confidence level",
    "severity": "Bandit's own severity level",
    "is_test_file": "file path looks like a test file",
    "has_dummy_keyword": "code contains a placeholder-like word (test/dummy/fake/changeme/...)",
    "has_tainted_input": "code reads from an external/user-controlled source nearby",
    "has_dynamic_concat": "code builds a string dynamically (concatenation/f-string/.format) rather than using a static literal",
    "secret_score": "the flagged value looks like a real secret (long and mixes character types)",
}
for _tid in ["B105", "B101", "B602", "B301", "B608", "B614", "B615"]:
    FEATURE_DESCRIPTIONS[f"rule_{_tid}"] = f"this is a {_tid} finding"


def describe_contribution(c: dict) -> str:
    name = c["feature"]
    present = c["raw_value"] >= 0.5
    desc = FEATURE_DESCRIPTIONS.get(name, name)
    if name in ("confidence", "severity"):
        return f"{desc} is {'high' if present else 'low'}"
    if name == "secret_score":
        # gradual 0..1 value: describe as high vs low, not present/absent
        return desc if present else "the flagged value looks more like a placeholder than a real secret"
    return desc if present else f"NOT true that {desc}"


def triage(report_path: str, model_path: str):
    findings = load_bandit_report(report_path)
    if not findings:
        print("No findings in this report (or it doesn't look like a Bandit JSON report).")
        return

    model = TriageClassifier.load(model_path)

    scored = []
    for f in findings:
        x = extract_features(f)
        pred = model.predict(x)
        scored.append((f, pred))

    # Highest priority first: most likely a true positive, then by Bandit's
    # own severity as a tiebreaker.
    severity_rank = {"HIGH": 2, "MEDIUM": 1, "LOW": 0}
    scored.sort(
        key=lambda item: (
            item[1].true_positive_probability,
            severity_rank.get(item[0].issue_severity.upper(), 0),
        ),
        reverse=True,
    )

    n_likely_tp = sum(1 for _, p in scored if p.label == "likely_true_positive")
    print(f"\n{len(scored)} findings triaged -- {n_likely_tp} likely true positive, "
          f"{len(scored) - n_likely_tp} likely false positive\n")

    for f, pred in scored:
        marker = "!!" if pred.label == "likely_true_positive" else "--"
        print(f"[{marker}] {f.filename}:{f.line_number}  ({f.test_id} {f.test_name})")
        print(f"     bandit says: {f.issue_text}")
        if f.cwe_id:
            print(f"     reference: CWE-{f.cwe_id} ({f.cwe_link})")
        print(f"     triage: {pred.label} (p={pred.true_positive_probability:.2f})")
        if pred.label == "likely_true_positive":
            top = pred.contributions[0]  # most positive contribution
        else:
            top = pred.contributions[-1]  # most negative contribution
        direction = "raises" if top["contribution"] > 0 else "lowers"
        print(f"     top reason: {describe_contribution(top)} ({direction} priority, contribution={top['contribution']:+.3f})")
        print()


def main():
    parser = argparse.ArgumentParser(description="Triage Bandit findings by predicted true-positive likelihood")
    subparsers = parser.add_subparsers(dest="command", required=True)

    triage_parser = subparsers.add_parser("triage", help="Triage a Bandit JSON report")
    triage_parser.add_argument("report", help="Path to a Bandit JSON report (bandit -f json -o report.json)")
    triage_parser.add_argument("--model", default="model.json", help="Path to the trained model JSON")

    args = parser.parse_args()

    if args.command == "triage":
        if not Path(args.report).exists():
            print(f"File not found: {args.report}", file=sys.stderr)
            sys.exit(1)
        if not Path(args.model).exists():
            print(f"Model not found: {args.model} -- run train_classifier.py first", file=sys.stderr)
            sys.exit(1)
        triage(args.report, args.model)


if __name__ == "__main__":
    main()