# bandit-triage

A small, explainable classifier that re-prioritizes findings from
[Bandit](https://github.com/PyCQA/bandit) (Python's most widely used
security static analyzer) by predicted true-positive likelihood, instead of
Bandit's own severity level alone.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — a visual explanation of the
  project structure and data flow (with diagrams), plus a file-by-file
  breakdown.
- [`docs/building-the-dataset.md`](docs/building-the-dataset.md) — the
  step-by-step process for growing the training dataset from real Bandit
  findings on real open-source projects, including the labeling policy used.

Reference for dataset construction: https://bandit.readthedocs.io/en/latest/plugins/index.html#complete-test-plugin-listing

## The problem

Static analysis tools are well documented to have high false-positive
rates in practice — deep-learning vulnerability detectors in particular are
known to perform well on curated benchmarks but degrade sharply on
real-world codebases, and recent research ([UntrustVul, 2025](https://arxiv.org/abs/2503.14852))
is specifically about identifying which vulnerability-detector alerts are
actually trustworthy. Bandit is excellent at *finding* patterns, but it has
no way to know that `assert` in your test suite is fine, that a hardcoded
`"changeme"` isn't a real secret, or that a `shell=True` call with a fully
static command string can't be exploited the same way one built from user
input can. Every one of those gets the same severity as a genuine issue,
which is exactly how alert fatigue happens.

## What this does

Takes Bandit's own JSON output and re-ranks it using a small logistic
regression classifier trained on hand-labeled examples of true vs. false
positives, with every prediction explained in plain language — not just a
re-sorted list. It also surfaces the CWE (Common Weakness Enumeration)
reference Bandit attaches to each finding, which the initial version of
this tool was silently discarding.

```bash
bandit -r . -f json -o bandit_results.json   # run real Bandit yourself
python3 -m bandit_triage.cli triage bandit_results.json --model model.json
```

Example output:

```
[!!] app/ml/upload_endpoint.py:19  (B614 pytorch_load)
     bandit says: Use of unsafe torch.load() -- can execute arbitrary code via pickle deserialization.
     reference: CWE-502 (https://cwe.mitre.org/data/definitions/502.html)
     triage: likely_true_positive (p=0.85)
     top reason: code reads from an external/user-controlled source nearby

[--] app/ml/startup.py:7  (B615 huggingface_unsafe_download)
     bandit says: Insecure download of Hugging Face model -- unpinned revision and trust_remote_code enabled.
     reference: CWE-494 (https://cwe.mitre.org/data/definitions/494.html)
     triage: likely_false_positive (p=0.18)
     top reason: NOT true that code reads from an external/user-controlled source nearby
```

## How it works

- **`loader.py`** — parses Bandit's real JSON schema (the format `bandit -f
  json` actually produces).
- **`features.py`** — turns each finding into a small, hand-designed
  feature vector: Bandit's own confidence/severity, whether the file looks
  like a test file, whether the flagged code contains a placeholder-like
  word, whether tainted external input (`request.`, `sys.argv`,
  user-uploaded files, unpinned model repo IDs, etc.) appears nearby,
  whether the code builds a string dynamically vs. using a static literal,
  a `secret_score` measuring how much a flagged value looks like a real
  secret rather than a placeholder, and which specific Bandit rule fired.
  Every feature is something a human reviewer would actually look for by
  hand.
- **`classifier.py`** — logistic regression trained on top of those
  features, saved as plain JSON (not pickle), with per-feature contribution
  explanations for every prediction.
- **`cli.py`** — runs the model against a real Bandit report and prints a
  re-prioritized, explained list.

## The dataset

`data/labeled_findings.json` contains hand-labeled example findings across
7 Bandit rule types (hardcoded passwords, `assert` usage, `subprocess` with
`shell=True`, `pickle` usage, string-built SQL queries, and Bandit's two
AI/ML supply-chain checks — unsafe `torch.load()` and insecure Hugging Face
model downloads, both of which map to CWE-502 insecure deserialization, the
same vulnerability class as the pickle research earlier in this project's
development). The dataset is grown by running Bandit on real open-source
projects and labeling the findings by hand; the two most developed rules so
far (B105 hardcoded passwords and B101 assert usage) are balanced with
around 20 examples each, while the others are still being filled in. See
[`docs/building-the-dataset.md`](docs/building-the-dataset.md) for the full
process and labeling policy, and Limitations below.

`data/sample_bandit_report.json` is a separate, held-out set of findings
(not used in training) used to sanity-check the classifier generalizes
past its exact training examples.

## Running it

```bash
pip install -r requirements.txt
python3 dataset_stats.py    # trains the model, saves model.json, and reports per-rule stats
python3 -m bandit_triage.cli triage data/sample_bandit_report.json --model model.json
```

`dataset_stats.py` is the main workhorse: it retrains the model on the
current dataset and writes two Markdown reports — `dataset_stats.md`
(per-rule true/false counts, training-set accuracy, and a balance hint) and
`misclassified.md` (the findings where the model disagrees with the hand
label, i.e. the hard cases). Note that the accuracy it reports is
*training-set* accuracy — a diagnostic, not a real held-out evaluation.

## Web UI (optional)

For a clearer view than terminal output, there's a minimal local web UI
(a Flask app with a dark "security tool" theme):

```bash
python3 web_ui.py
# then open http://127.0.0.1:5001
```

Paste a Bandit JSON report into the box (or click "Load example report"),
and it renders each finding as a color-coded card — red for likely-real
issues, grey for likely-noise — sorted most-likely-real first, each with
its CWE reference, the plain-language reason for the verdict, and the
offending code snippet. It uses the exact same triage logic as the CLI, so
the two always agree.

**How it's built.** The UI is a [Flask](https://flask.palletsprojects.com/)
app — a lightweight Python web framework, chosen so the interface stays in
the same language as the rest of the project and adds no heavy dependencies.
A single route accepts the pasted report via an HTML form, passes it to the
same `triage_report` logic the CLI uses, and renders the results with a
Jinja2 template (`templates/index.html`) styled by a separate stylesheet
(`static/style.css`). It runs over plain HTTP on `localhost`, which is
appropriate here: the browser and server are the same machine, so no data
crosses a network — HTTPS would only matter for a public deployment. For the
same reason it runs in Flask's debug mode (auto-reload on file changes);
both debug mode and plain HTTP should be turned off if this were ever exposed
beyond localhost.

## Limitations

- **The training set is small and partly hand-written.** It started from
  synthetic examples and is being grown with real findings labeled by hand
  (see [`docs/building-the-dataset.md`](docs/building-the-dataset.md)). This
  is a research prototype demonstrating the approach, not a validated
  production tool. With more data, the model's explanations would likely
  become more consistently intuitive — on the current small dataset, one or
  two predictions land on a technically-correct but less obviously-relevant
  top explanation, a visible symptom of training on so few examples.
- **The features are hand-designed heuristics, not learned representations
  of code semantics.** A more advanced version could use an AST-based or
  code-embedding representation instead of regex-based signals like
  "contains a placeholder-like word."
- **This only re-prioritizes existing Bandit findings — it doesn't find
  anything Bandit itself misses**, and it inherits any blind spots in
  Bandit's own rule set.
- **Every rule type needs its own true-positive/false-positive examples to
  be useful.** The current rule types were chosen because they have
  well-understood, describable true/false-positive patterns; extending
  coverage to Bandit's full rule set would need proportionally more labeled
  data per rule.
- **The model is only reliable for the rule types present in the dataset.**
  It still produces a prediction for any Bandit finding, but for rules it
  wasn't trained on it falls back to generic context signals only, without
  knowing what kind of issue it is — so treat those predictions with more
  caution. Extending coverage means adding labeled examples of the new rule,
  not just listing its ID (see `docs/architecture.md`).

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
│   ├── architecture.md            # structure & data flow, with diagrams
│   └── building-the-dataset.md    # how the dataset is grown from real findings
├── templates/
│   └── index.html                 # web UI markup
├── static/
│   └── style.css                  # web UI styling (dark theme)
├── inspect_findings.py            # helper to inspect real Bandit findings by rule
├── add_to_dataset.py              # helper to add labeled findings to the dataset
├── dataset_stats.py               # trains the model + writes per-rule stats and misclassified reports
├── web_ui.py                      # optional local web UI
└── requirements.txt
```