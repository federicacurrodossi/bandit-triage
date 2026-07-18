"""
Prints and saves a breakdown of the labeled dataset: for each Bandit rule,
how many true_positive vs false_positive examples it has, a simple balance
flag, and the training-set accuracy (how many the model gets right on the
data it learned from), plus overall totals.

IMPORTANT: training-set accuracy is a DIAGNOSTIC, not a real evaluation. It
measures the model on the same data it was trained on, so it looks
optimistic. A real evaluation needs a separate held-out test set. Use it to
see which rules the model struggles with, not to claim real-world accuracy.

Run it whenever you want to check the state of the dataset:
    python3 dataset_stats.py

It trains the model on the current dataset, prints the table to the screen,
and also writes it to:
    dataset_stats.txt
"""
import json
from collections import defaultdict

import numpy as np

from bandit_triage.classifier import TriageClassifier
from bandit_triage.features import extract_features
from bandit_triage.loader import load_labeled_data

DATASET_PATH = "data/labeled_findings.json"
OUTPUT_PATH = "dataset_stats.txt"

# target per rule, used only to show a simple hint (not enforced)
TARGET_PER_RULE = 20
MIN_MINORITY = 6  # aim for at least this many of the smaller class


def main():
    # load findings (both as raw dicts for counting and as Finding objects
    # for feature extraction / accuracy)
    with open(DATASET_PATH) as f:
        data = json.load(f)

    findings = load_labeled_data(DATASET_PATH)
    X = np.array([extract_features(f) for f in findings])
    y = np.array([1 if f.label == "true_positive" else 0 for f in findings])

    # train the model on the full dataset so we can report accuracy
    model = TriageClassifier.train(X, y)
    model.save("model.json")

    # count per rule and label, and track correct predictions per rule
    counts = defaultdict(lambda: {"true_positive": 0, "false_positive": 0,
                                  "correct": 0, "total": 0})
    for finding, x, label in zip(findings, X, y):
        rule = finding.test_id or "UNKNOWN"
        if label == 1:
            counts[rule]["true_positive"] += 1
        else:
            counts[rule]["false_positive"] += 1

        pred = model.predict(x)
        predicted = 1 if pred.label == "likely_true_positive" else 0
        counts[rule]["correct"] += int(predicted == label)
        counts[rule]["total"] += 1

    lines = []
    lines.append("Dataset balance and training-set accuracy by rule")
    lines.append("=" * 72)
    lines.append("NOTE: accuracy is a diagnostic (measured on the training data itself),")
    lines.append("not a real evaluation. A real evaluation needs a held-out test set.")
    lines.append("")
    lines.append(f"{'rule':8} {'true':>5} {'false':>6} {'total':>6} {'accuracy':>11}   balance")
    lines.append("-" * 72)

    total_tp = total_fp = total_correct = 0
    for rule in sorted(counts.keys()):
        tp = counts[rule]["true_positive"]
        fp = counts[rule]["false_positive"]
        total = tp + fp
        correct = counts[rule]["correct"]
        total_tp += tp
        total_fp += fp
        total_correct += correct

        acc = correct / total if total else 0.0
        acc_str = f"{correct}/{total} ({acc:>4.0%})"

        # simple balance hint
        minority = min(tp, fp)
        if total < TARGET_PER_RULE:
            hint = f"need ~{TARGET_PER_RULE - total} more to reach {TARGET_PER_RULE}"
        elif minority < MIN_MINORITY:
            smaller = "true" if tp < fp else "false"
            hint = f"unbalanced: only {minority} {smaller} (aim for >= {MIN_MINORITY})"
        else:
            hint = "ok"

        lines.append(f"{rule:8} {tp:>5} {fp:>6} {total:>6} {acc_str:>11}   {hint}")

    grand_total = total_tp + total_fp
    overall_acc = total_correct / grand_total if grand_total else 0.0
    lines.append("-" * 72)
    lines.append(f"{'TOTAL':8} {total_tp:>5} {total_fp:>6} {grand_total:>6} "
                 f"{f'{total_correct}/{grand_total} ({overall_acc:.0%})':>11}")
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