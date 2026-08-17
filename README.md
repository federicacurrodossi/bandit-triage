# Bandit triage

A small, explainable classifier that re-ranks
[Bandit](https://github.com/PyCQA/bandit) findings by how likely they are to be
real, instead of relying on Bandit's severity alone.

## Why

Bandit spots patterns but can't tell that an `assert` in your tests is fine,
that a hardcoded `"changeme"` isn't a real secret, or that `shell=True` with a
fixed command isn't the same risk as one built from user input. All land with
the same severity as a genuine issue, and that's how alert fatigue starts.

This follows from how Bandit assigns severity and confidence: they are not
computed from your code, they are fixed values the plugin author hardcoded for
the rule. Every B608 finding returns MEDIUM/MEDIUM whether the query is a real
injection or a harmless internal template, because the plugin returns
`Issue(severity=MEDIUM, confidence=MEDIUM)` regardless of context. (A few rules
vary within a rule: B105 drops to LOW confidence when it can't read the value,
MEDIUM when it's `None` or `False`.) So severity and confidence describe the
*rule*, not the specific finding. This tool learns how much to trust those
fixed labels by reading the context Bandit ignores.

## What it does

It reads Bandit's JSON output and re-sorts it with a logistic regression model
trained on hand-labeled true and false positives. Every prediction comes with a
plain-language reason and the CWE reference Bandit attaches.

```bash
# step 1: run Bandit, which writes the report
bandit -r path/to/your/project -f json -o bandit_results.json
# step 2: this tool re-ranks that report
python3 -m bandit_triage.cli triage bandit_results.json --model model.json
```

Point Bandit at a specific package rather than `.` if the tree has a `venv` or
vendored code, otherwise the report fills with third-party findings.

Take two B608 findings from the held-out set. Bandit reports both identically
(MEDIUM severity, MEDIUM confidence), but they are opposites.

A real injection, from a keylogger backend, where `device_id` comes straight
from the request:

```python
@app.route("/fetch")
def fetch_data():
    device_id = str(request.args.get("device_id"))          # untrusted
    data = execute(f"SELECT * FROM keystrokes where device_id='{device_id}'")
```

A safe query, from Django's cache backend, where the interpolated value is an
internal table name run through `quote_name`, never user input:

```python
def clear(self):
    table = connection.ops.quote_name(self._table)          # internal identifier
    with connection.cursor() as cursor:
        cursor.execute("DELETE FROM %s" % table)
```

The tool tells them apart:

```
[!!] keylogger/app.py:46  (B608 hardcoded_sql_expressions)
     triage: likely_true_positive (p=0.93)
     top reason: untrusted input (request, route parameter, user input) reaches this line (raises priority, contribution=+3.559)

[--] django/core/cache/backends/db.py:302  (B608 hardcoded_sql_expressions)
     triage: likely_false_positive (p=0.43)
     top reason: no untrusted input reaches this line (the value is internal or constant) (lowers priority, contribution=-0.395)
```

The taint engine follows `device_id` back to `request.args` in the first case
(untrusted, so likely real), but finds only an internal constant in the second,
which is exactly the reason each finding is ranked the way it is.

## Running it

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 dataset_stats.py
python3 -m bandit_triage.cli triage data/sample_bandit_report.json --model model.json
```

Activate the venv: `bandit` installs into `venv/bin`, so a bare `bandit` won't
resolve without it. `dataset_stats.py` retrains on the current dataset, writes
`model.json`, and produces `dataset_stats.md` (per-rule counts and accuracy) and
`misclassified.md`. That accuracy is training-set accuracy, a diagnostic; the
real check is the held-out set (see `docs/evaluation.md`).

## How it works

* `loader.py` parses Bandit's JSON.
* `features.py` builds a small hand-designed feature vector per finding:
  confidence and severity, whether it's a test file, whether the value looks
  like a placeholder, whether tainted input reaches the sink and whether a
  sanitizer sits on the way (for B608 these come from the taint engine; other
  rules use a regex), whether a string is built dynamically, a `secret_score`,
  and which rule fired.
* `classifier.py` is logistic regression over those features, stored as plain
  JSON (not a pickle), with per-feature contributions behind every prediction.
* `cli.py` runs the model over a report and prints the re-ranked list.

## Web UI (optional)

```bash
python3 web_ui.py
# open http://127.0.0.1:5001
```

Paste a Bandit report (or click "Load example report") and each finding renders
as a color-coded card, most likely real first, with its CWE reference, the
reason, and the snippet. It calls the same `triage_report` logic as the CLI. It
runs over plain HTTP on localhost with debug on, fine for local use but to be
turned off before exposing anywhere.

## The dataset

`data/labeled_findings.json` holds hand-labeled findings across three rules,
chosen to cover the two shapes of finding the project handles. Two are decided
by a static signal because the origin of the data doesn't matter: `assert` usage
(B101, test vs production) and hardcoded passwords (B105, real secret vs
placeholder). The third is an injection rule where origin is everything:
string-built SQL (B608), dangerous with user input and harmless with an internal
identifier.

Other partially-labeled rules (pickle B301, subprocess B602, the ML supply-chain
checks B614/B615) are set aside in `data/archive/` rather than deleted. They are
flow rules that need the data-flow analysis this project is building out, so
they wait there without losing the labeling work.

`heldout/` holds hand-labeled held-out sets, never used in training.

## Limitations

* The training set is small and started from synthetic examples: a research
  prototype, not a production tool.
* The features are hand-written heuristics, not learned representations. An AST
  or embedding based version would be a step up.
* It only re-ranks what Bandit found, and inherits Bandit's blind spots.
* Each rule needs its own labeled examples; untrained rules fall back to generic
  signals and deserve more scrutiny.
* The held-out evaluation (`docs/evaluation.md`) makes this concrete: on 63
  unseen findings from Django and two vulnerable Flask apps the model reaches
  92% accuracy (F1 0.92). Because it's explainable, each error names the feature
  responsible. Two such leads were already followed: the data-flow work, and a
  content-based `is_test_file` that reads a file for a `TestCase` class rather
  than trusting the word "test" in its path, taking B101 recall from 0.75 to 1.00.
* The data-flow work is a small intra-procedural taint analysis
  (`bandit_triage/taint.py`, see `docs/taint-engine.md`) that traces each value
  back to its origin instead of widening the snippet by a fixed amount. It's the
  boundary Semgrep's free tier draws; inter-procedural flow is left to CodeQL and
  reported as unknown. Wired into the features, it catches the injections the old
  regex missed and lifted the B608 held-out from 2 to 8 true positives (F1 0.78).
  The remaining static-template false positives turn on Bandit's confidence and a
  `return f"..."` sink shape the engine doesn't yet cover.

## Docs

* [`docs/architecture.md`](docs/architecture.md): structure and data flow.
* [`docs/building-the-dataset.md`](docs/building-the-dataset.md): how the dataset
  is grown, and the labeling policy.
* [`docs/evaluation.md`](docs/evaluation.md): how the model is tested on held-out
  findings.
* [`docs/taint-engine.md`](docs/taint-engine.md): the taint engine design.
* [`docs/rule-coverage.md`](docs/rule-coverage.md): which Bandit rules are
  covered, trained, and tested.

## Repo structure

```
bandit-triage/
├── bandit_triage/
│   ├── loader.py
│   ├── features.py
│   ├── taint.py                  # intra-procedural taint analysis
│   ├── classifier.py
│   └── cli.py
├── data/
│   ├── labeled_findings.json     # training data
│   ├── archive/                  # set-aside flow rules, awaiting the engine
│   └── sample_bandit_report.json
├── docs/                         # architecture, dataset, evaluation, taint-engine, rule-coverage
├── heldout/                      # hand-labeled held-out test sets
├── b101_spec.txt                 # reproducible held-out specs
├── b608_spec.txt
├── tests/                        # taint engine unit tests
├── inspect_findings.py           # inspect Bandit findings by rule
├── add_to_dataset.py             # add labeled findings to the dataset
├── dataset_stats.py              # train + write stats
├── split_findings_by_rule.py     # split a report into one file per rule
├── build_heldout.py              # build a held-out set from a spec and reports
├── embed_functions.py            # bake enclosing functions into a findings JSON
├── evaluate_heldout.py           # evaluate on the held-out sets
├── web_ui.py
└── requirements.txt
```