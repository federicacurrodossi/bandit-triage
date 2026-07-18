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
- **python-insecure-app** (`github.com/trottomv/python-insecure-app`) — a
  deliberately vulnerable FastAPI app. It contributed a clear B105 true
  positive (`SUPER_SECRET_TOKEN = "5u93R53Cr3tT0k3n"`, a realistic token in a
  config file) plus two false positives (`SUPER_SECRET_NAME = "John Ripper"`,
  a joke placeholder value — one in config, one in a test file). A good
  illustration that the variable name alone ("SECRET") doesn't decide the
  label; the value and context do.

Sources that were tried but did not contribute: **flask_config_example**
(`github.com/MirelaI/flask_config_example`) was scanned but produced no B105
findings, because it keeps its secrets in a `config.json` file rather than in
Python code, and Bandit only analyzes `.py` files. It's recorded here for
transparency — not every source yields usable findings, and knowing why is
part of the process.

This split matters: training only on Flask would teach the model only what
noise looks like. Pairing it with Bandit's intentional examples and
vulnerable teaching repos gives the model both sides — real issues and false
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

Use the `add_to_dataset.py` helper, which copies findings from a Bandit
report straight into `data/labeled_findings.json` in the correct format
(no editing JSON by hand). You give it the report, the rule, the label, and
which finding numbers to add (the numbers match what `inspect_findings.py`
prints):

```bash
# add B105 findings #1 and #3 as false positive
python3 add_to_dataset.py insecure_app_findings.json B105 false_positive 1,3

# add B105 finding #2 as true positive
python3 add_to_dataset.py insecure_app_findings.json B105 true_positive 2
```

It shows a preview, asks for confirmation, and backs up the dataset before
writing. (You can still edit `data/labeled_findings.json` by hand instead —
each entry is all the fields Bandit produced plus the hand-added `label`.)

### 6. If it's a new rule type, register it

If you're adding a rule the model hasn't seen before, also add its ID to
`KNOWN_TEST_IDS` in `bandit_triage/features.py`, so the model gets a feature
for it.

### 7. Retrain and check the balance

Run `dataset_stats.py`. It retrains the model on the updated dataset (saving
`model.json`) and prints a per-rule report: how many true/false positive
examples each rule has, the training-set accuracy, and a balance hint telling
you which rules still need more examples.

```bash
python3 dataset_stats.py
```

Note: the accuracy shown is training-set accuracy — a diagnostic measured on
the same data the model learned from, not a real evaluation. A real
evaluation needs a separate held-out test set. Use the report to spot which
rules are unbalanced or which the model struggles with, not to claim
real-world accuracy.

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

## Constructed true-positive examples for B105

Real hardcoded secrets are rare in clean open-source projects, so the B105
true-positive class was hard to fill from real repos alone (Flask had none,
and the intentionally-vulnerable repos gave only a handful). To balance the
class, a few true-positive examples were deliberately constructed — using
**real, publicly documented secret formats**, not values invented at random,
and not anyone's actual leaked secret. They live in
`constructed_secrets_example.py`.

Where the patterns come from (documented sources):

- **AWS secret access key** — the 40-character `[A-Za-z0-9/+=]{40}` format,
  using AWS's own public example value `wJalrXUtnFEMI/...EXAMPLEKEY` (note the
  literal word "EXAMPLE" in it). Sources: AWS Secrets Manager / CloudFormation
  documentation, and the Cencori "Secrets Detection Patterns" list.
- **JWT signing secret** — the `eyJhbGci...` base64 header shape that every
  HS256 JWT starts with. Sources: Cencori pattern list; AWS Kendra "JWT with
  a shared secret" documentation.
- **MongoDB connection string** — `mongodb+srv://user:pass@cluster...` with an
  embedded password. Source: Cencori pattern list
  (`mongodb(\+srv)?://[^@\s]+@...`).
- **Stripe API key** — the `sk_test_[0-9a-zA-Z]{24,}` format, using Stripe's
  public documentation test key. Sources: Cencori pattern list; Stripe docs.
- **SMTP password** — a generic high-complexity password (mixed case, digits,
  symbols), matching the generic `(password|passwd|pwd)` pattern.

Why they're built this way (design rationale):

- **Different *shapes* of secret** — a cloud key, a token, a connection
  string, an API key, and a password. This teaches the model that a B105 true
  positive comes in many forms, not just one, so it generalizes better than
  it would from five near-identical passwords.
- **All in production (non-test) files**, and all actually *used* — each
  secret is passed to a function that consumes it (`boto3.Session`,
  `jwt.encode`, `MongoClient`, `stripe.api_key`, `smtp.login`). So the
  context clearly indicates a real, active credential, not a dead placeholder.
- **Values use documented public example formats**, so they have the right
  length and character variety of real secrets (and therefore score high on
  the `secret_score` feature) without being anyone's actual leaked secret.

A note on Bandit coverage: Bandit's B105 only fires when the flagged string is
tied to a **name** containing `password`, `pass`, `passwd`, `pwd`, `secret`,
`token`, or `secrete`. So of the five, Bandit flags `AWS_SECRET_ACCESS_KEY`,
`JWT_SECRET`, and `SMTP_PASSWORD`, but **not** `STRIPE_API_KEY` or
`DATABASE_URL` — even though those are just as real. That gap is intentional
and useful: the two Bandit misses were added to the dataset by hand, so the
triage model learns to recognize them by value and context. If Bandit's rule
ever widens to catch them, the model is already prepared. This is a small
demonstration that the triage layer can reason about secrets beyond Bandit's
current pattern matching.

This is disclosed openly: these are constructed examples with realistic
shape, clearly marked as such — not scraped real-world leaks. Using public
example values (like AWS's `...EXAMPLEKEY` and Stripe's documentation test
key) is a deliberate choice so the dataset contains no genuine live secret.

## Per-rule reasoning: B101 (assert_used)

B101 flags every use of the `assert` keyword. The reason it matters: asserts
are **stripped out** when Python is compiled to optimized bytecode
(`python -O`), so any check written as an `assert` silently disappears in that
mode. If an assert was enforcing something important, that protection is gone.
Bandit's own advice is to raise a real error (`AssertionError` or a meaningful
exception) instead. B101 is always severity LOW, confidence HIGH — Bandit is
sure it's an assert; it just can't know whether it matters in context.

The key labeling signal for B101 is almost the mirror image of B105's, and it
turns on **where the assert is**:

- **assert in a test file** → `false_positive`. Using `assert` in unit tests
  is the normal, expected way to check results (`assert result == expected`).
  Bandit itself documents skipping this rule in tests (its `assert_used`
  config suggests skipping `*_test.py` / `*test_*.py`). The `is_test_file`
  feature captures this directly, so the model handles it well.
- **assert in production / application code** → `true_positive`. Here the
  assert could vanish under `python -O`, so per the rule it should be replaced
  with a real error. We label these true positive consistently, on principle.

A worked illustration from Flask: scanning the whole project produced **1053**
B101 findings, but **1049** of them were in test files (legitimate test
asserts → false positive) and only **4** were in the actual source under
`src/flask/` (e.g. `assert view_func is not None` in `scaffold.py`,
`assert meth is not None` in `views.py`). Those 4 are the interesting
true-positive candidates. This lopsided split (1049 vs 4) is itself the
lesson: for B101, real issues are rare and the "where" question does almost
all the work.

An honest note on the borderline: the 4 source asserts in Flask are true
positives *by the rule* (asserts in production code, removable under `-O`),
but in practice they guard developer-side invariants (type checks, internal
preconditions) rather than security-critical protections. A strict reviewer
labels them true positive on principle; a pragmatic one might see them as
low-risk defensive checks. We label them `true_positive` for a consistent,
defensible policy — but the ambiguity is deliberately kept, because these grey
cases are exactly what makes triage a non-trivial judgment rather than a
lookup.