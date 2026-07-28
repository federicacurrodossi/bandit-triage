"""
Prints and saves a breakdown of the labeled dataset: for each Bandit rule,
how many true_positive vs false_positive examples it has, a balance flag, and
the training-set accuracy. It ALSO writes a second file listing every finding
the model misclassifies (where its prediction disagrees with your hand label),
grouped by rule -- so you can inspect the hard cases after every training run
without running a separate script.

IMPORTANT: training-set accuracy is a DIAGNOSTIC, not a real evaluation. It
measures the model on the same data it was trained on, so it looks optimistic.
A real evaluation needs a separate held-out test set.

Run whenever you want to check the dataset:
    python3 dataset_stats.py

Writes:
    dataset_stats.md     -- the per-rule distribution + accuracy table
    misclassified.md     -- every finding the model got wrong, grouped by rule
"""
import json
from collections import defaultdict

import numpy as np

from bandit_triage.classifier import TriageClassifier
from bandit_triage.features import extract_features, secret_score, extract_flagged_value
from bandit_triage.loader import load_labeled_data

DATASET_PATH = "data/labeled_findings.json"
OUTPUT_PATH = "dataset_stats.md"
MISCLASSIFIED_PATH = "misclassified.md"

TARGET_PER_RULE = 20
MIN_MINORITY = 6


def main():
    findings = load_labeled_data(DATASET_PATH)
    X = np.array([extract_features(f) for f in findings])
    y = np.array([1 if f.label == "true_positive" else 0 for f in findings])

    # train on the full dataset
    model = TriageClassifier.train(X, y)
    model.save("model.json")

    # per-rule counts + accuracy, and collect misclassified findings
    counts = defaultdict(lambda: {"tp": 0, "fp": 0, "correct": 0, "total": 0})
    misclassified = defaultdict(list)  # rule -> list of (finding, pred)

    for f, x, label in zip(findings, X, y):
        rule = f.test_id or "UNKNOWN"
        if label == 1:
            counts[rule]["tp"] += 1
        else:
            counts[rule]["fp"] += 1

        pred = model.predict(x)
        predicted = 1 if pred.label == "likely_true_positive" else 0
        counts[rule]["correct"] += int(predicted == label)
        counts[rule]["total"] += 1

        if predicted != label:
            misclassified[rule].append((f, pred))

    # ---- gather per-rule rows ----
    rows = []
    total_tp = total_fp = total_correct = 0
    for rule in sorted(counts.keys()):
        d = counts[rule]
        tp, fp = d["tp"], d["fp"]
        total = tp + fp
        correct = d["correct"]
        total_tp += tp
        total_fp += fp
        total_correct += correct

        acc = correct / total if total else 0.0
        acc_str = f"{correct}/{total} ({acc:.0%})"

        minority = min(tp, fp)
        if total < TARGET_PER_RULE:
            hint = f"need ~{TARGET_PER_RULE - total} more to reach {TARGET_PER_RULE}"
        elif minority < MIN_MINORITY:
            smaller = "true" if tp < fp else "false"
            hint = f"unbalanced: only {minority} {smaller} (aim for >= {MIN_MINORITY})"
        else:
            hint = "ok"

        rows.append((rule, tp, fp, total, acc_str, hint))

    grand_total = total_tp + total_fp
    overall_acc = total_correct / grand_total if grand_total else 0.0
    total_wrong = sum(len(v) for v in misclassified.values())

    # ---- console output (aligned plain text) ----
    console = []
    console.append("Dataset balance and training-set accuracy by rule")
    console.append("=" * 72)
    console.append(f"{'rule':8} {'true':>5} {'false':>6} {'total':>6} {'accuracy':>12}   balance")
    console.append("-" * 72)
    for rule, tp, fp, total, acc_str, hint in rows:
        console.append(f"{rule:8} {tp:>5} {fp:>6} {total:>6} {acc_str:>12}   {hint}")
    console.append("-" * 72)
    console.append(f"{'TOTAL':8} {total_tp:>5} {total_fp:>6} {grand_total:>6} "
                   f"{f'{total_correct}/{grand_total} ({overall_acc:.0%})':>12}")
    console.append(f"\nRules covered: {len(counts)} | "
                   f"{total_tp} true, {total_fp} false | "
                   f"misclassified: {total_wrong}")
    print("\n".join(console))

    # ---- Markdown output for the file ----
    lines = []
    lines.append("# Dataset balance and training-set accuracy")
    lines.append("")
    lines.append("> **Note:** accuracy here is *training-set* accuracy — a diagnostic "
                 "measured on the same data the model learned from, so it looks "
                 "optimistic. A real evaluation needs a separate held-out test set. "
                 "Use it to spot unbalanced rules or ones the model struggles with, "
                 "not to claim real-world accuracy.")
    lines.append("")
    lines.append("| Rule | True | False | Total | Accuracy | Balance |")
    lines.append("|------|-----:|------:|------:|:--------:|---------|")
    for rule, tp, fp, total, acc_str, hint in rows:
        lines.append(f"| {rule} | {tp} | {fp} | {total} | {acc_str} | {hint} |")
    lines.append(f"| **TOTAL** | **{total_tp}** | **{total_fp}** | **{grand_total}** | "
                 f"**{total_correct}/{grand_total} ({overall_acc:.0%})** | |")
    lines.append("")
    lines.append(f"- **Rules covered:** {len(counts)}")
    lines.append(f"- **Overall:** {total_tp} true_positive, {total_fp} false_positive")
    lines.append(f"- **Misclassified:** {total_wrong} (see `{MISCLASSIFIED_PATH}`)")

    table_text = "\n".join(lines)
    with open(OUTPUT_PATH, "w") as fh:
        fh.write(table_text + "\n")

    # ---- build the misclassified report as Markdown, grouped by rule ----
    mlines = []
    mlines.append("# Misclassified findings")
    mlines.append("")
    mlines.append("_Cases where the model's prediction disagrees with your hand label._")
    mlines.append("")
    mlines.append("> A disagreement is often a genuinely **ambiguous** finding "
                  "(fine to miss), not necessarily a labeling error. Use this to "
                  "decide, per case, whether it's healthy ambiguity (leave it) or "
                  "a label worth revising.")
    mlines.append("")

    total_wrong = sum(len(v) for v in misclassified.values())
    if total_wrong == 0:
        mlines.append("**None** — the model agrees with every label. ✅")
    else:
        mlines.append(f"**Total misclassified: {total_wrong}**")
        mlines.append("")
        for rule in sorted(misclassified.keys()):
            mlines.append(f"## {rule} — {len(misclassified[rule])} misclassified")
            mlines.append("")
            for f, pred in misclassified[rule]:
                value = extract_flagged_value(f)
                mlines.append(f"### `{f.filename}:{f.line_number}`")
                mlines.append("")
                mlines.append(f"- **Your label:** {f.label}")
                mlines.append(f"- **Model says:** {pred.label} "
                              f"(p={pred.true_positive_probability:.2f})")
                if value:
                    mlines.append(f"- **Flagged value:** `{value}` "
                                  f"(secret_score = {secret_score(value):.2f})")
                # show the signal that pushed most toward the model's own
                # (wrong) verdict: the most-positive contribution when it
                # predicted true, the most-negative when it predicted false.
                # This matches describe_contribution() in cli.py and explains
                # *why the model decided as it did*, rather than always showing
                # the most-positive feature regardless of the verdict.
                if pred.label == "likely_true_positive":
                    top = pred.contributions[0]
                else:
                    top = pred.contributions[-1]
                mlines.append(f"- **Top signal:** {top['feature']} "
                              f"(contribution = {top['contribution']:+.2f})")
                mlines.append("")
                mlines.append("```python")
                mlines.append(f.code.strip())
                mlines.append("```")
                mlines.append("")

    mtext = "\n".join(mlines)
    with open(MISCLASSIFIED_PATH, "w") as fh:
        fh.write(mtext + "\n")

    print(f"\n[Saved table to {OUTPUT_PATH} and misclassified report to {MISCLASSIFIED_PATH}]")


if __name__ == "__main__":
    main()