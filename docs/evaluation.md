# Evaluating the model

How the model is tested on findings it was never trained on, to measure
whether it actually generalizes rather than just memorizing its training data.

## Why a held-out set is needed

`dataset_stats.py` reports an accuracy figure, but that number is measured on
the same findings the model trained on. It is a diagnostic (useful for
spotting unbalanced rules or obvious problems), not a real evaluation: a model
can score well there just by memorizing its training data. To know whether the
model generalizes, it has to be tested on findings it has never seen.

A held-out set is exactly that: findings from a project that contributed
nothing to training, hand-labeled with the same policy used for the training
data. The accuracy on this set is an honest estimate of how the model behaves
on new code.

## Choosing a source

The held-out project has to be one the model was never trained on, so none of
the training sources (Flask, Bandit's examples, the vulnerable teaching repos,
Werkzeug) qualify. **Django** was used: a large, mature framework that shares
no findings with the training set. Being large helps, because it produces
enough findings per rule to make the numbers meaningful.

There is no public dataset of "Bandit findings labeled true or false" to pull
from, so the held-out set is built the same way the training set is: scan a
real project, then label the output by hand.

## The process

### 1. Scan a fresh project

```bash
git clone --depth 1 https://github.com/django/django.git target_django
bandit -r target_django -f json -o django_findings.json
```

`target_django/` and `django_findings.json` are regenerated on demand, so they
are gitignored.

### 2. Split the report by rule

```bash
python3 split_findings_by_rule.py django_findings.json django_findings/
```

This writes one file per rule (`django_findings/B101.json`, etc.), so each
rule can be inspected and labeled on its own. The `django_findings/` output
folder is gitignored; the script is not.

### 3. Label a sample by hand, before looking at the model

A large project produces far too many findings to label all of them (Django
alone has 70 B101 findings), so a representative sample is taken per rule,
covering both labels. The labels are decided with the same three-question
policy used for the training data, and crucially **before** running the model.
Labeling after seeing the model's predictions would contaminate the test: the
point is an independent judgment to compare against.

Labels are recorded in a small **spec file**: one finding per line, as
`<label> <path-substring>:<line>`. The path only has to be a unique substring
of the finding's filename, so the full path is not needed. Lines starting with
`#` are comments. For example:

```
false_positive core/cache/backends/db.py:136
true_positive  main.py:25
```

### 4. Build the held-out file from real findings

Each rule keeps **one spec file** (for example `b608_spec.txt`), and it holds
every case for that rule regardless of which project it came from. When new
cases turn up in another project, you add their lines to the same spec; you do
not start a second spec.

`build_heldout.py` takes that one spec, plus **all** the Bandit reports the
findings live in, searches every report to find each finding by path and line,
copies it verbatim (real code, confidence, line numbers, not retyped), attaches
the hand label, and writes the held-out file:

```bash
python3 build_heldout.py b608_spec.txt heldout/heldout_b608.json \
    django_findings/B608.json hackable_findings.json
```

The argument order is: spec, then output, then one or more reports. Because the
script pools all the reports together, a spec line is matched wherever its
finding actually is (the Django cases resolve against `django_findings/B608.json`,
the hackable cases against `hackable_findings.json`). Adding a third project
later means adding its lines to the spec and its report to the command, nothing
else.

Held-out files are grouped **one per rule** (`heldout/heldout_b101.json`,
`heldout/heldout_b608.json`). Unlike the raw scans, the spec and the held-out
file are committed: they are hand-made test data, the same kind of artifact as
`data/labeled_findings.json`.

A note on why several sources are needed. A clean framework like Django gives
plenty of *false* positives for a rule (its ORM builds SQL from internal
identifiers, which Bandit flags but which are safe), but no *true* positives,
because a mature project has no real SQL injection. The true positives come
from deliberately vulnerable teaching apps (for B608, a small Flask app whose
login and search endpoints paste `request` data straight into the query). One
rule's held-out set therefore mixes both: safe-but-flagged queries from real
code, and genuine injections from vulnerable apps.

### 5. Evaluate the whole folder at once

```bash
python3 evaluate_heldout.py heldout/
```

Pointing the evaluator at the `heldout/` folder runs **every** rule file in it
in one go, so a change that fixes one rule but quietly breaks another is caught
immediately (regression testing). It loads the trained model, predicts each
finding, compares against the hand label, and writes `heldout_stats.md` with
accuracy, precision, recall, F1, a confusion matrix, and a per-rule breakdown
that lists every misclassified finding with the feature that drove the model's
decision. Adding a new rule file to the folder needs no change here: it is
picked up automatically on the next run.

## What the numbers mean

* **Accuracy** is the share of findings the model labeled the way the reviewer
  did.
* **Precision** (for the true-positive class) is how often the model is right
  when it says "true positive". High precision means few false alarms, which is
  what makes a triage tool trustworthy: it isn't crying wolf.
* **Recall** is how many of the real true positives the model actually caught.
* **F1** balances precision and recall in a single number.

Because the model is explainable, a misclassified finding is not a dead end:
the report shows which feature pushed the model toward its wrong answer, so
each error points at a concrete, fixable cause rather than being random noise.

## Worked example: B101 on Django

The first held-out evaluation used 32 hand-labeled B101 findings from Django
(20 true positives from production code, 12 false positives from real test
files). At first the model scored 27/32 (84%), and every one of the five errors
was the same kind of case, which the report named directly: findings under
`django/test/`, Django's testing *framework* (production code that happens to
live in a folder called `test`), not actual tests. The `is_test_file` feature
only checked whether "test" appeared in the path, so it fired on these and
pushed the model to "false positive". The reviewer labeled them true positive,
because they are production asserts that vanish under `python -O` like any other.

This is the held-out set doing its job: the errors were not random, they exposed
one precise, understandable limitation. The fix followed the lead. `is_test_file`
now reads the file for a `TestCase` class (content), or accepts a `tests/`
directory or `test_*.py` name (path), which tells `django/test/` (production)
apart from `tests/` (real tests and their support code). B101 recall rose from
0.75 to 1.00 and its accuracy to 31/32 (97%), lifting the whole held-out set to
53/57 (93%), F1 0.92. This is the kind of concrete, fixable insight an
explainable model gives that a black-box classifier would not.

## Extending the evaluation

Adding a rule to the evaluation is the same five steps: scan a project, split
by rule, label a spec, build the rule's held-out file from the spec and the
reports, and re-run `evaluate_heldout.py heldout/`. Adding a *new source* to a
rule already covered is smaller still: add the new cases to that rule's
existing spec, add the new report to the build command, and rebuild. Because
each rule lives in its own file and the evaluator reads the whole folder, rules
accumulate independently and the regression test always covers all of them at
once.

Growing each rule's held-out set to 30 to 50 findings makes its numbers
steadier, since with a small sample a single case moves the accuracy by several
points. Pulling those cases from more than one project also makes the estimate
more honest: it shows the model generalizing across codebases, not just fitting
the quirks of one.