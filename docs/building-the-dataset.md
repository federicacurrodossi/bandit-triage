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

## Step-by-step process

### 1. Get a real project to scan

```bash
git clone --depth 1 https://github.com/pallets/flask.git target_flask
```

### 2. Run Bandit on it and save the JSON output

```bash
bandit -r target_flask -f json -o real_findings.json
```

This produces `real_findings.json`: the raw findings, exactly as Bandit
reports them. Note that Bandit findings do **not** contain a `label` field —
Bandit flags patterns but never judges whether they're real problems in
context. Adding that judgment is our job.

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

## Honest note for the README

Documenting this process is itself a strength of the project: it shows the
dataset was built by applying a consistent, explainable labeling policy to
real findings from real projects — not by inventing convenient examples.
When the dataset grows this way, the model's evaluation becomes far more
credible.
