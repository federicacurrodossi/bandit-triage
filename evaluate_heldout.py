"""
Evaluate the trained model on a held-out labeled set: findings the model was
never trained on, hand-labeled with the same policy used for the training data.

Unlike the training-set accuracy that dataset_stats.py reports (measured on the
same data the model learned from), this is a real evaluation: it measures how
well the model generalizes to unseen findings from a different project.

The held-out file is a Bandit report whose findings each carry a "label"
field ("true_positive" / "false_positive"), added by hand.

Usage:
    python3 evaluate_heldout.py heldout_b101.json
    python3 evaluate_heldout.py heldout_b101.json --model model.json
"""
import argparse
import json
from pathlib import Path

from bandit_triage.classifier import TriageClassifier
from bandit_triage.features import extract_features
from bandit_triage.loader import Finding, _extract_cwe


def load_labeled_report(path):
    """Load a Bandit report whose findings carry a hand-added 'label' field."""
    with open(path) as f:
        data = json.load(f)
    items = []
    for it in data.get("results", []):
        cwe_id, cwe_link = _extract_cwe(it)
        finding = Finding(
            filename=it["filename"],
            code=it.get("code", ""),
            issue_confidence=it.get("issue_confidence", "MEDIUM"),
            issue_severity=it.get("issue_severity", "MEDIUM"),
            issue_text=it.get("issue_text", ""),
            line_number=it.get("line_number", 0),
            test_id=it.get("test_id", ""),
            test_name=it.get("test_name", ""),
            cwe_id=cwe_id,
            cwe_link=cwe_link,
            function_code=it.get("function_code"),
            sink_text=it.get("sink_text"),
        )
        label = it.get("label")
        if label not in ("true_positive", "false_positive"):
            raise ValueError(f"finding {finding.filename}:{finding.line_number} has no valid label")
        items.append((finding, label))
    return items


def collect_report_paths(paths):
    """Expand the given paths into a sorted list of report files. A directory
    contributes every .json file inside it; a file is taken as-is. This lets the
    held-out sets stay as separate per-rule files while a single command
    evaluates all of them together (regression testing)."""
    collected = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            collected.extend(sorted(path.glob("*.json")))
        elif path.is_file():
            collected.append(path)
        else:
            print(f"skipping missing path: {p}")
    # de-duplicate while preserving order
    seen = set()
    unique = []
    for path in collected:
        rp = path.resolve()
        if rp not in seen:
            seen.add(rp)
            unique.append(path)
    return unique


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("heldout", nargs="+",
                    help="held-out report file(s) or a directory of them "
                         "(each finding needs a 'label' field)")
    ap.add_argument("--model", default="model.json")
    ap.add_argument("--out", default="heldout_stats.md",
                    help="Markdown report to write (default: heldout_stats.md)")
    args = ap.parse_args()

    model = TriageClassifier.load(args.model)

    report_paths = collect_report_paths(args.heldout)
    if not report_paths:
        print("No held-out report files found.")
        return

    items = []
    for rp in report_paths:
        items.extend(load_labeled_report(rp))

    # confusion-matrix counters, tracked overall and per rule
    tp = fp = tn = fn = 0
    wrong = []
    # rule -> dict with its own counters and its own misclassified list
    per_rule = {}

    for finding, true_label in items:
        pred = model.predict(extract_features(finding))
        predicted_true = pred.label == "likely_true_positive"
        actual_true = true_label == "true_positive"

        rule = finding.test_id or "UNKNOWN"
        r = per_rule.setdefault(rule, {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "wrong": []})

        if predicted_true and actual_true:
            tp += 1; r["tp"] += 1
        elif predicted_true and not actual_true:
            fp += 1; r["fp"] += 1
        elif not predicted_true and not actual_true:
            tn += 1; r["tn"] += 1
        else:
            fn += 1; r["fn"] += 1

        if predicted_true != actual_true:
            wrong.append((finding, true_label, pred))
            r["wrong"].append((finding, true_label, pred))

    total = len(items)
    correct = tp + tn
    acc = correct / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    # ---- console output ----
    source_names = ", ".join(p.name for p in report_paths)
    print(f"Held-out evaluation on {len(report_paths)} file(s): {source_names}")
    print("=" * 60)
    print(f"Findings: {total}  ({tp + fn} true, {tn + fp} false by hand label)")
    print(f"Accuracy:  {correct}/{total} ({acc:.0%})")
    print(f"Precision: {precision:.2f}  Recall: {recall:.2f}  F1: {f1:.2f}")
    print(f"Misclassified: {len(wrong)}")
    print(f"\n[Saved report to {args.out}]")

    # ---- Markdown report ----
    lines = []
    lines.append("# Held-out evaluation")
    lines.append("")
    if len(report_paths) == 1:
        lines.append(f"Source: `{report_paths[0].name}`")
    else:
        lines.append(f"Sources ({len(report_paths)} files): "
                     + ", ".join(f"`{p.name}`" for p in report_paths))
    lines.append("")
    lines.append("> A real evaluation on findings the model was never trained on, "
                 "hand-labeled with the same policy as the training data. Unlike the "
                 "training-set accuracy in `dataset_stats.md`, this measures how well "
                 "the model generalizes to unseen code from a different project.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Findings | {total} ({tp + fn} true, {tn + fp} false) |")
    lines.append(f"| Accuracy | {correct}/{total} ({acc:.0%}) |")
    lines.append(f"| Precision (true_positive) | {precision:.2f} |")
    lines.append(f"| Recall (true_positive) | {recall:.2f} |")
    lines.append(f"| F1 score | {f1:.2f} |")
    lines.append("")
    lines.append("## Confusion matrix (overall)")
    lines.append("")
    lines.append("| | predicted true | predicted false |")
    lines.append("|--|--|--|")
    lines.append(f"| **actual true** | {tp} | {fn} |")
    lines.append(f"| **actual false** | {fp} | {tn} |")
    lines.append("")

    # per-rule breakdown: one section per rule, so the report is already
    # organized by rule even when only one rule has been evaluated so far.
    lines.append("## Results by rule")
    lines.append("")
    for rule in sorted(per_rule):
        r = per_rule[rule]
        r_tp, r_fp, r_tn, r_fn = r["tp"], r["fp"], r["tn"], r["fn"]
        r_total = r_tp + r_fp + r_tn + r_fn
        r_correct = r_tp + r_tn
        r_acc = r_correct / r_total if r_total else 0.0
        r_prec = r_tp / (r_tp + r_fp) if (r_tp + r_fp) else 0.0
        r_rec = r_tp / (r_tp + r_fn) if (r_tp + r_fn) else 0.0
        r_f1 = (2 * r_prec * r_rec / (r_prec + r_rec)) if (r_prec + r_rec) else 0.0

        lines.append(f"### {rule}")
        lines.append("")
        lines.append(f"- **Accuracy:** {r_correct}/{r_total} ({r_acc:.0%})")
        lines.append(f"- **Precision / Recall / F1:** {r_prec:.2f} / {r_rec:.2f} / {r_f1:.2f}")
        lines.append(f"- **Confusion:** TP {r_tp}, FP {r_fp}, TN {r_tn}, FN {r_fn}")
        lines.append("")

        if not r["wrong"]:
            lines.append("No misclassified findings for this rule: the model agreed "
                         "with every hand label.")
            lines.append("")
        else:
            lines.append(f"**Misclassified ({len(r['wrong'])}):** the informative cases, "
                         "worth reading to see where the model's signals fall short.")
            lines.append("")
            for finding, true_label, pred in r["wrong"]:
                lines.append(f"#### `{finding.filename}:{finding.line_number}`")
                lines.append("")
                lines.append(f"- **Hand label:** {true_label}")
                lines.append(f"- **Model says:** {pred.label} "
                             f"(p={pred.true_positive_probability:.2f})")
                top = pred.contributions[0] if pred.label == "likely_true_positive" else pred.contributions[-1]
                lines.append(f"- **Top signal:** {top['feature']} "
                             f"(contribution = {top['contribution']:+.2f})")
                lines.append("")
                if finding.code:
                    lines.append("```python")
                    lines.append(finding.code.strip())
                    lines.append("```")
                    lines.append("")

    Path(args.out).write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()