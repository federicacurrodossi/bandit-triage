# Bandit triage

A small, explainable classifier that re-ranks findings from
[Bandit](https://github.com/PyCQA/bandit) by how likely they are to be real,
instead of relying on Bandit's severity level alone.

## Why

Bandit is good at spotting patterns, but it can't tell that an `assert` in
your test suite is fine, that a hardcoded `"changeme"` isn't a real secret,
or that `shell=True` with a fixed command string isn't the same risk as one
built from user input. All of those land with the same severity as a genuine
issue, and that's how alert fatigue starts.

## What it does

It reads Bandit's own JSON output and re-sorts it using a logistic regression
model trained on hand-labeled true and false positives. Every prediction comes
with a plain-language reason, plus the CWE reference Bandit attaches to the
finding.

```bash
# step 1 runs Bandit itself and writes the report file
bandit -r path/to/your/project -f json -o bandit_results.json
# step 2 is this tool, reading the file step 1 just wrote
python3 -m bandit_triage.cli triage bandit_results.json --model model.json
```

`bandit_results.json` is generated, not checked in, so it won't exist until you
run step 1. Point Bandit at a specific package rather than `.` if your project
has a `venv` or vendored code sitting in the tree, otherwise the report fills up
with findings from third party code.

```
[!!] app/ml/upload_endpoint.py:19  (B614 pytorch_load)
     bandit says: Use of unsafe torch.load(), can execute arbitrary code via pickle deserialization.
     reference: CWE-502 (https://cwe.mitre.org/data/definitions/502.html)
     triage: likely_true_positive (p=0.85)
     top reason: code reads from an external/user-controlled source nearby

[--] app/ml/startup.py:7  (B615 huggingface_unsafe_download)
     bandit says: Insecure download of Hugging Face model, unpinned revision and trust_remote_code enabled.
     reference: CWE-494 (https://cwe.mitre.org/data/definitions/494.html)
     triage: likely_false_positive (p=0.18)
     top reason: NOT true that code reads from an external/user-controlled source nearby
```

## Running it

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 dataset_stats.py
python3 -m bandit_triage.cli triage data/sample_bandit_report.json --model model.json
```

Activating the venv matters: `bandit` installs into `venv/bin`, so a bare
`bandit` command won't resolve without it.

`dataset_stats.py` does the heavy lifting: it retrains on the current dataset,
writes `model.json`, and produces two reports. `dataset_stats.md` has per-rule
counts and accuracy, and `misclassified.md` lists the cases where the model
disagrees with the hand label. The accuracy figure is training-set accuracy,
so treat it as a diagnostic rather than a real evaluation.

## How it works

* `loader.py` parses Bandit's actual JSON schema.
* `features.py` builds a small hand-designed feature vector per finding:
  Bandit's confidence and severity, whether the file looks like a test file,
  whether the flagged value looks like a placeholder, whether tainted input
  (`request.`, `sys.argv`, uploads, unpinned model IDs) shows up nearby,
  whether a string is built dynamically or written as a literal, a
  `secret_score`, and which rule fired. These are the things a reviewer
  checks by hand anyway.
* `classifier.py` is logistic regression on top of those features, stored as
  plain JSON rather than a pickle, with per-feature contributions behind every
  prediction.
* `cli.py` runs the model over a report and prints the re-ranked list.

## Web UI (optional)

There's a small local Flask app if you'd rather read the results in a browser:

```bash
python3 web_ui.py
# open http://127.0.0.1:5001
```

Paste in a Bandit report (or click "Load example report") and each finding
renders as a color-coded card, most likely real first, with its CWE reference,
the reason for the verdict, and the offending snippet. It calls the same
`triage_report` logic as the CLI, so the two never disagree. It runs over
plain HTTP on localhost with debug mode on, which is fine when the browser and
server are the same machine. Both would need turning off before exposing it
anywhere else.

## The dataset

`data/labeled_findings.json` holds hand-labeled findings across 7 Bandit rule
types: hardcoded passwords, `assert` usage, `subprocess` with `shell=True`,
`pickle`, string-built SQL, and the two AI/ML supply chain checks (unsafe
`torch.load()` and insecure Hugging Face downloads, both CWE-502). It grows by
running Bandit on real open source projects and labeling by hand. B105 and
B101 are the most developed, with roughly 20 examples each; the rest are still
filling in.

`data/sample_bandit_report.json` is a held-out set, never used in training, for
checking that the model generalizes past its exact examples.

## Limitations

* The training set is small and started from synthetic examples. This is a
  research prototype, not a production tool. On a dataset this size, a
  prediction occasionally picks a technically correct but oddly chosen top
  explanation.
* The features are hand-written heuristics, not learned representations of
  code semantics. An AST or embedding based version would be a real step up.
* It only re-ranks what Bandit already found, and inherits every blind spot in
  Bandit's rule set.
* Each rule type needs its own labeled examples. Predictions for untrained
  rules fall back to generic context signals, so give those more scrutiny.
  Adding a rule means adding labeled examples, not just listing the ID.

## Docs

* [`docs/architecture.md`](docs/architecture.md): structure and data flow, with
  diagrams and a file by file breakdown.
* [`docs/building-the-dataset.md`](docs/building-the-dataset.md): how the
  dataset is grown, including the labeling policy.
* Bandit's own [plugin listing](https://bandit.readthedocs.io/en/latest/plugins/index.html#complete-test-plugin-listing),
  used as the reference for dataset construction.

## Repo structure

```
bandit-triage/
├── bandit_triage/
│   ├── loader.py
│   ├── features.py
│   ├── classifier.py
│   └── cli.py
├── data/
│   ├── labeled_findings.json     # training data
│   └── sample_bandit_report.json # held-out test data
├── docs/
│   ├── architecture.md
│   └── building-the-dataset.md
├── templates/index.html          # web UI markup
├── static/style.css              # web UI styling
├── inspect_findings.py           # inspect real Bandit findings by rule
├── add_to_dataset.py             # add labeled findings to the dataset
├── dataset_stats.py              # train + write stats and misclassified reports
├── web_ui.py
└── requirements.txt
```
