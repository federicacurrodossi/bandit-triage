"""
Prints and saves a breakdown of the labeled dataset: for each Bandit rule,
how many true_positive vs false_positive examples it has, plus totals and a
simple balance flag.

Run it whenever you want to check the state of the dataset:
    python3 dataset_stats.py

It prints the table to the screen and also writes it to:
    dataset_stats.txt
"""
import json
from collections import defaultdict

DATASET_PATH = "data/labeled_findings.json"
OUTPUT_PATH = "dataset_stats.txt"

# target per rule, used only to show a simple hint (not enforced)
TARGET_PER_RULE = 20
MIN_MINORITY = 6  # aim for at least this many of the smaller class


def main():
    with open(DATASET_PATH) as f:
        data = json.load(f)
    findings = data["findings"]

    # count per rule and label
    counts = defaultdict(lambda: {"true_positive": 0, "false_positive": 0})
    for item in findings:
        rule = item.get("test_id", "UNKNOWN")
        label = item.get("label", "unlabeled")
        if label in ("true_positive", "false_positive"):
            counts[rule][label] += 1

    lines = []
    lines.append("Dataset balance by rule")
    lines.append("=" * 60)
    lines.append(f"{'rule':8} {'true':>5} {'false':>6} {'total':>6}   balance")
    lines.append("-" * 60)

    total_tp = total_fp = 0
    for rule in sorted(counts.keys()):
        tp = counts[rule]["true_positive"]
        fp = counts[rule]["false_positive"]
        total = tp + fp
        total_tp += tp
        total_fp += fp

        # simple balance hint
        minority = min(tp, fp)
        if total < TARGET_PER_RULE:
            hint = f"need ~{TARGET_PER_RULE - total} more to reach {TARGET_PER_RULE}"
        elif minority < MIN_MINORITY:
            smaller = "true" if tp < fp else "false"
            hint = f"unbalanced: only {minority} {smaller} (aim for >= {MIN_MINORITY})"
        else:
            hint = "ok"

        lines.append(f"{rule:8} {tp:>5} {fp:>6} {total:>6}   {hint}")

    lines.append("-" * 60)
    lines.append(f"{'TOTAL':8} {total_tp:>5} {total_fp:>6} {total_tp + total_fp:>6}")
    lines.append("")
    lines.append(f"Rules covered: {len(counts)}")
    lines.append(f"Overall: {total_tp} true_positive, {total_fp} false_positive")

    text = "\n".join(lines)
    print(text)

    with open(OUTPUT_PATH, "w") as f:
        f.write(text + "\n")
    print(f"\n[Saved to {OUTPUT_PATH}]")


if __name__ == "__main__":
    main()
