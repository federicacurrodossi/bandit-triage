"""
Split a Bandit JSON report into one file per rule (test_id).

Given a full Bandit report, this writes an output directory containing one JSON
file per rule that appears in it (B101.json, B608.json, ...), each holding only
the findings for that rule, in the same Bandit report format. That makes it
easy to inspect and label one rule at a time, e.g. for building a held-out
evaluation set from a project the model was never trained on.

Usage:
    python3 split_findings_by_rule.py django_findings.json django_findings/

    # then, per rule:
    python3 inspect_findings.py django_findings/B608.json B608

If the output directory is omitted, it defaults to "<report_stem>_by_rule/".
"""
import json
import sys
from collections import defaultdict
from pathlib import Path


def main():
    if len(sys.argv) < 2:
        print("usage: python3 split_findings_by_rule.py <report.json> [output_dir/]")
        sys.exit(1)

    report_path = Path(sys.argv[1])
    if not report_path.exists():
        print(f"File not found: {report_path}")
        sys.exit(1)

    if len(sys.argv) >= 3:
        out_dir = Path(sys.argv[2])
    else:
        out_dir = report_path.with_name(report_path.stem + "_by_rule")

    with open(report_path) as f:
        report = json.load(f)

    results = report.get("results", [])
    if not results:
        print("No findings in this report.")
        sys.exit(0)

    # group findings by their rule id
    by_rule = defaultdict(list)
    for finding in results:
        rule = finding.get("test_id", "UNKNOWN")
        by_rule[rule].append(finding)

    out_dir.mkdir(parents=True, exist_ok=True)

    # write one file per rule, preserving the top-level report keys
    # (errors, generated_at, metrics) so each file is a valid Bandit report
    base_keys = {k: v for k, v in report.items() if k != "results"}
    for rule in sorted(by_rule):
        rule_report = dict(base_keys)
        rule_report["results"] = by_rule[rule]
        out_path = out_dir / f"{rule}.json"
        with open(out_path, "w") as f:
            json.dump(rule_report, f, indent=2)

    # summary, most frequent first
    print(f"Wrote {len(by_rule)} rule files to {out_dir}/\n")
    print(f"{'rule':8} {'findings':>8}")
    print("-" * 18)
    for rule, items in sorted(by_rule.items(), key=lambda kv: len(kv[1]), reverse=True):
        print(f"{rule:8} {len(items):>8}")
    total = sum(len(v) for v in by_rule.values())
    print("-" * 18)
    print(f"{'TOTAL':8} {total:>8}")


if __name__ == "__main__":
    main()