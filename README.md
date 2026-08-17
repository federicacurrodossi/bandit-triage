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
[!!] app/db/queries.py:41  (B608 hardcoded_sql_expressions)
     bandit says: Possible SQL injection vector through string-based query construction.
     reference: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)
     triage: likely_true_positive (p=0.85)
     top reason: code reads from an external/user-controlled source nearby

[--] app/db/backend.py:88  (B608 hardcoded_sql_expressions)
     bandit says: Possible SQL injection vector through string-based query construction.
     reference: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)
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
  reaches the sink and whether a sanitizer sits on the way (for B608 these two
  come from the taint engine, following the value back to its origin; other
  rules fall back to a regex over the snippet), whether a string is built
  dynamically or written as a literal, a `secret_score`, and which rule fired.
  These are the things a reviewer checks by hand anyway.
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

`data/labeled_findings.json` holds hand-labeled findings across three Bandit
rule types, chosen so the project covers the two shapes of finding it needs to
handle. Two are rules where the origin of the data does not matter, so a static
signal decides them: `assert` usage (B101, test file vs production) and
hardcoded passwords (B105, real secret vs placeholder). The third is an
injection rule where origin is everything: string-built SQL (B608), where the
same query shape is dangerous with user input and harmless with an internal
identifier.

Other rules that were partially labeled earlier (pickle B301, `subprocess`
B602, and the AI/ML supply-chain checks B614/B615) are set aside in
`data/archive/` rather than deleted. They are all flow rules whose findings
really need the data-flow analysis this project is now building out (see
`docs/architecture.md`), so they wait there until that engine covers them,
without losing the labeling work already done.

`heldout/` holds hand-labeled held-out sets, never used in training, for
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
* The held-out evaluation (see [`docs/evaluation.md`](docs/evaluation.md))
  makes these concrete. On 63 unseen findings from Django and two vulnerable
  Flask apps the model reaches 92% accuracy (F1 0.92). The errors are
  informative and, because the model is explainable, each one names the feature
  responsible, which points directly at what to improve. Two such leads have
  already been followed: the data-flow work below, and a content-based
  `is_test_file` that reads a file for a `TestCase` class rather than trusting
  the word "test" in its path, which took B101 recall from 0.75 to 1.00.
* The data-flow work targets exactly these errors. Rather than widening the
  snippet by a fixed amount (an arbitrary, fragile heuristic), the project adds
  a small intra-procedural taint analysis (`bandit_triage/taint.py`, described
  in [`docs/taint-engine.md`](docs/taint-engine.md)) that works backward from
  the sink to the origin of each value, following assignments through the
  function no matter how far apart they are. This is the boundary Semgrep's free
  tier also draws; inter-procedural flow across functions and files is left to
  heavier tools like CodeQL and reported honestly as unknown.
* Wired into the features, the engine catches the real SQL injections the old
  regex missed: the Flask route parameter case, and eight true positives
  collected from vulnerable apps (a keylogger backend that pastes `request` data
  into INSERT, UPDATE, and SELECT queries), lifting the B608 held-out from 2 to
  8 true positives and its F1 to 0.78. The static template false positives that
  remain are no longer a data-flow problem (the engine correctly stops calling
  them tainted); they turn on Bandit's confidence and on a sink shape
  (`return f"..."`) the engine does not yet cover.

## Docs

* [`docs/architecture.md`](docs/architecture.md): structure and data flow, with
  diagrams and a file by file breakdown.
* [`docs/building-the-dataset.md`](docs/building-the-dataset.md): how the
  dataset is grown, including the labeling policy.
* [`docs/evaluation.md`](docs/evaluation.md): how the model is tested on
  held-out findings from projects it was never trained on, the real
  generalization check rather than training-set accuracy.
* Bandit's own [plugin listing](https://bandit.readthedocs.io/en/latest/plugins/index.html#complete-test-plugin-listing),
  used as the reference for dataset construction.

## Repo structure

```
bandit-triage/
├── bandit_triage/
│   ├── loader.py
│   ├── features.py
│   ├── taint.py
│   ├── classifier.py
│   └── cli.py
├── data/
│   ├── labeled_findings.json     # training data
│   └── sample_bandit_report.json # held-out test data
├── docs/
│   ├── architecture.md
│   ├── building-the-dataset.md
│   ├── evaluation.md             # held-out evaluation methodology
│   └── taint-engine.md           # taint engine design and validation
├── heldout/                      # hand-labeled held-out test sets
│   ├── heldout_b101.json
│   └── heldout_b608.json
├── b101_spec.txt                 # reproducible spec for the B101 held-out
├── b608_spec.txt                 # reproducible spec for the B608 held-out
├── templates/index.html          # web UI markup
├── static/style.css              # web UI styling
├── inspect_findings.py           # inspect real Bandit findings by rule
├── add_to_dataset.py             # add labeled findings to the dataset
├── dataset_stats.py              # train + write stats and misclassified reports
├── split_findings_by_rule.py     # split a Bandit report into one file per rule
├── build_heldout.py              # build a held-out set from a spec and reports
├── embed_functions.py            # bake enclosing functions into a findings JSON
├── evaluate_heldout.py           # evaluate the model on the held-out sets
├── web_ui.py
└── requirements.txt
```