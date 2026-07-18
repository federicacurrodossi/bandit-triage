# Building the dataset from real Bandit findings

This document describes the process used to grow the training dataset
(`data/labeled_findings.json`) with **real** findings, instead of only the
initial synthetic examples.

## The idea

The model learns to imitate a human reviewer's judgment: given a Bandit
finding, decide whether it's a real issue worth fixing (`true_positive`) or
noise that can be safely ignored (`false_positive`). To learn that well, it
needs realistic examples — so instead of inventing them, we take real
findings produced by running Bandit on real open-source Python projects, and
label them by hand.

We use **Flask** (`github.com/pallets/flask`) as the first source of real
code. It's a well-known, mature project, so its findings are realistic and
mostly represent the "noise" case a reviewer meets in practice (asserts in
tests, dummy passwords in examples, etc.) — good material for learning to
tell signal from noise.

### Sources used so far

Different sources contribute different kinds of examples, and a good dataset
needs both:

- **Flask** (`github.com/pallets/flask`) — a mature, well-reviewed project.
  Its findings are almost entirely **false positives** (dummy passwords in
  tests, `SECRET_KEY: None` defaults, placeholder values), because a clean
  project has no real secrets committed to code. Good for the "noise" side.
- **Bandit's own examples** (`github.com/PyCQA/bandit`, the `examples/`
  folder) — files written deliberately to trigger Bandit's rules, so they
  are the most authoritative source of **true positives**. For B105 they
  contain realistic hardcoded-secret patterns that a clean project like Flask
  simply doesn't have.
- **Intentionally-Vulnerable-Python-Application**
  (`github.com/mukxl/Intentionally-Vulnerable-Python-Application`) — a
  deliberately vulnerable teaching repo. Its hardcoded `admin` /
  `password123` credential is a clear B105 true positive: a stored
  authentication credential in application (non-test) code. This is the kind
  of realistic case clean projects don't contain. Used deliberately and
  disclosed here as an intentionally vulnerable source; the finding was still
  labeled by hand using the policy below, not assumed true just because the
  repo is labeled "vulnerable".

Sources that were tried but did not contribute: **flask_config_example**
(`github.com/MirelaI/flask_config_example`) was scanned but produced no B105
findings, because it keeps its secrets in a `config.json` file rather than in
Python code, and Bandit only analyzes `.py` files. It's recorded here for
transparency — not every source yields usable findings, and knowing why is
part of the process.

This split matters: training only on Flask would teach the model only what
noise looks like. Pairing it with Bandit's intentional examples and a
vulnerable teaching repo gives the model both sides — real issues and false
alarms — which is what it needs to tell them apart.

Note on true positives: examples from intentionally-vulnerable or
example repositories are realistic but deliberately constructed (a password
put there on purpose). That's fine and expected — a genuinely leaked
production secret is rare and hard to find, for good reason. What matters is
that the example has the right *shape* of a true positive: a realistic-looking
value, in production (non-test) code, actually used to authenticate. This is
disclosed openly rather than presented as scraped real-world leaks.

## Step-by-step process

### 1. Get a real project to scan

```bash
# a clean project (mostly false positives)
git clone --depth 1 https://github.com/pallets/flask.git target_flask

# Bandit's own intentional examples (a good source of true positives)
git clone --depth 1 https://github.com/PyCQA/bandit.git target_bandit
```

Remember to add the cloned folders and generated reports to `.gitignore`
(`target_flask/`, `target_bandit/`, `real_findings.json`,
`bandit_examples.json`, `findings_*.txt`) so they never get committed to your
own repo.

### 2. Run Bandit on it and save the JSON output

```bash
# scan Flask
bandit -r target_flask -f json -o real_findings.json

# scan Bandit's examples folder (for true positives)
bandit -r target_bandit/examples -f json -o bandit_examples.json
```

This produces JSON reports: the raw findings, exactly as Bandit reports them.
Note that Bandit findings do **not** contain a `label` field — Bandit flags
patterns but never judges whether they're real problems in context. Adding
that judgment is our job.

### 3. Inspect the findings one rule at a time

Looking at all findings at once is overwhelming (Flask produces over a
thousand, mostly low-severity). So we focus on one rule type at a time.

First, see the summary of how many findings there are per rule:

```bash
python3 inspect_findings.py real_findings.json
```

Then look at the details of a single rule (e.g. B105, hardcoded passwords):

```bash
python3 inspect_findings.py real_findings.json B105
```

This prints each finding and also writes a worksheet file
(`findings_B105.txt`) with a `LABEL: ____` line under each finding to fill
in by hand.

### 4. Label each finding by hand

For each finding, decide `true_positive` or `false_positive` by asking three
questions about the **context** (not just trusting Bandit's severity):

1. **Where is it?** A file under `tests/` or `examples/` leans toward
   false positive.
2. **What is the value?** An obviously fake value (`"a"`, `"test"`,
   `"changeme"`) leans false positive; a realistic secret (`"sk_live_..."`,
   `"pr0d-p@ssw0rd"`) leans true positive.
3. **What does the code do with it?** Filling in a test form is harmless;
   authenticating to a real production database is serious.

Important: Bandit's **severity is just one clue, not the answer**. Bandit can
rate something HIGH that's actually a false positive (e.g. `shell=True` on a
fixed, safe command), or LOW that's actually a true positive (e.g. a real
production API key it underestimates). The label reflects the real
context, decided by the reviewer.

### 5. Add the labeled findings to the dataset

Copy the labeled findings into `data/labeled_findings.json`, in the same
format as the existing entries (all the fields Bandit produced, plus the
`label` field added by hand).

### 6. If it's a new rule type, register it

If you're adding a rule the model hasn't seen before, also add its ID to
`KNOWN_TEST_IDS` in `bandit_triage/features.py`, so the model gets a feature
for it.

### 7. Retrain and check

```bash
python3 train_classifier.py
```

Then run the triage on a held-out report to see how it behaves on findings
it wasn't trained on.

## Worked example

A real B105 finding from Flask:

```
file:  target_flask/examples/tutorial/tests/test_auth.py  (line 13)
severity: LOW | confidence: MEDIUM
text:  Possible hardcoded password: 'a'
code:
    13   response = client.post("/auth/register", data={"username": "a", "password": "a"})
```

Reasoning: it's in a `tests/` file inside `examples/` (question 1 → test
code), the password is `"a"`, an obviously fake single character (question 2
→ fake value), and the code is just simulating a registration to test a
redirect (question 3 → harmless). All three point the same way.

**Label: `false_positive`.**
