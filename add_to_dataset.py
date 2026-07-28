"""
Add labeled findings from a real Bandit report into the training dataset
(data/labeled_findings.json), in the exact format the dataset uses, without
editing JSON by hand.

You tell it which rule, which finding numbers, and which label; it copies
those findings from the Bandit report and appends them to the dataset with
the label attached.

Usage:
    # add B105 findings #1,2,3,4,5,6,7,8,9 from the report, all as false_positive
    python3 add_to_dataset.py real_findings.json B105 false_positive 1-9

    # add just findings #2 and #5 as false_positive
    python3 add_to_dataset.py real_findings.json B105 false_positive 2,5

    # add a single finding #1 as true_positive
    python3 add_to_dataset.py real_findings.json B602 true_positive 1

The finding numbers match what `inspect_findings.py` prints (1-based, within
that rule).

Nothing is added until you confirm.
"""
import json
import sys

DATASET_PATH = "data/labeled_findings.json"

# only these fields are copied into the dataset (the schema the model uses);
# extra Bandit fields like col_offset / line_range / more_info are dropped
KEEP_FIELDS = [
    "filename",
    "code",
    "issue_confidence",
    "issue_severity",
    "issue_text",
    "line_number",
    "test_id",
    "test_name",
]


def parse_selection(selection: str):
    """Turns '1-9' or '2,5' or '1-3,7' into a list of 1-based indices."""
    indices = set()
    for part in selection.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            indices.update(range(int(start), int(end) + 1))
        elif part:
            indices.add(int(part))
    return sorted(indices)


def main():
    if len(sys.argv) != 5:
        print(__doc__)
        sys.exit(1)

    report_path, rule_id, label, selection = sys.argv[1:5]

    if label not in ("true_positive", "false_positive"):
        print(f"Label must be 'true_positive' or 'false_positive', got: {label}")
        sys.exit(1)

    # load the Bandit report and pick out the findings for this rule
    with open(report_path) as f:
        report = json.load(f)
    rule_findings = [r for r in report.get("results", []) if r["test_id"] == rule_id]

    if not rule_findings:
        print(f"No {rule_id} findings in {report_path}.")
        sys.exit(1)

    wanted = parse_selection(selection)
    to_add = []
    for idx in wanted:
        if idx < 1 or idx > len(rule_findings):
            print(f"  (skipping #{idx}: only {len(rule_findings)} {rule_id} findings exist)")
            continue
        raw = rule_findings[idx - 1]
        entry = {field: raw.get(field) for field in KEEP_FIELDS}
        entry["label"] = label
        to_add.append(entry)

    if not to_add:
        print("Nothing to add.")
        sys.exit(0)

    # show what will be added and ask for confirmation
    print(f"\nAbout to add {len(to_add)} finding(s) as '{label}':\n")
    for e in to_add:
        print(f"  {e['filename']}:{e['line_number']}  {e['issue_text']}")
    answer = input(f"\nAppend these to {DATASET_PATH}? [y/N] ").strip().lower()
    if answer != "y":
        print("Cancelled. Nothing changed.")
        sys.exit(0)

    with open(DATASET_PATH) as f:
        dataset = json.load(f)
    dataset["findings"].extend(to_add)
    with open(DATASET_PATH, "w") as f:
        json.dump(dataset, f, indent=2)

    print(f"\nDone. Added {len(to_add)} finding(s).")
    print(f"Dataset now has {len(dataset['findings'])} findings total.")


if __name__ == "__main__":
    main()