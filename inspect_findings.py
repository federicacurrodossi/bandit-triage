"""
Helper to inspect the findings in a Bandit report, filtered by rule type
(test_id). Use it to look at findings one by one while you decide the
true_positive / false_positive label for each.

Besides printing to the screen, it writes the output to a text file, with a
"LABEL: ____" line under each finding that you can fill in by hand as you
decide.

Usage:
    python3 inspect_findings.py real_findings.json B105
    python3 inspect_findings.py real_findings.json B602
    python3 inspect_findings.py real_findings.json          (shows the per-rule summary)

The output file is saved as:
    findings_<TEST_ID>.txt      (e.g. findings_B105.txt)
    findings_summary.txt         (for the summary)
"""
import json
import sys
from collections import Counter


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 inspect_findings.py <report.json> [TEST_ID]")
        sys.exit(1)

    report_path = sys.argv[1]
    rule_filter = sys.argv[2] if len(sys.argv) > 2 else None

    with open(report_path) as f:
        data = json.load(f)

    results = data.get("results", [])

    # Collect the output lines in a list, so we can both print them to the
    # screen and write them to the file with identical content.
    lines = []

    if rule_filter is None:
        # Summary mode
        lines.append(f"Total findings: {len(results)}")
        lines.append("")
        by_rule = Counter((r["test_id"], r["test_name"]) for r in results)
        lines.append("Findings per rule (most frequent first):")
        for (tid, name), count in by_rule.most_common():
            lines.append(f"  {tid}  {name}: {count}")
        lines.append("")
        lines.append("Re-run with a TEST_ID to see the details, e.g.:")
        lines.append(f"  python3 inspect_findings.py {report_path} B105")
        out_path = "findings_summary.txt"
    else:
        # Detail mode for a single rule
        filtered = [r for r in results if r["test_id"] == rule_filter]
        lines.append(f"Found {len(filtered)} {rule_filter} findings")
        lines.append("")
        for i, r in enumerate(filtered):
            lines.append(f"--- {rule_filter} #{i + 1} ---")
            lines.append(f"file:       {r['filename']}  (line {r['line_number']})")
            lines.append(f"severity:   {r['issue_severity']}  |  confidence: {r['issue_confidence']}")
            lines.append(f"text:       {r['issue_text']}")
            lines.append("code:")
            for code_line in r["code"].rstrip("\n").split("\n"):
                lines.append(f"    {code_line}")
            # a line ready to fill in by hand with true_positive / false_positive
            lines.append("LABEL: ____________   (true_positive / false_positive)")
            lines.append("")
        out_path = f"findings_{rule_filter}.txt"

    text = "\n".join(lines)

    # print to screen
    print(text)

    # save to file
    with open(out_path, "w") as f:
        f.write(text + "\n")

    print(f"\n[Output also saved to: {out_path}]")


if __name__ == "__main__":
    main()