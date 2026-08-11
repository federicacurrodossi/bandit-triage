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

The labeled sample is saved as a Bandit report where each finding carries an
added `label` field, under `heldout/` (for example `heldout/heldout_b101.json`).
Unlike the raw scans, this file is committed: it is hand-made test data, the
same kind of artifact as `data/labeled_findings.json`.

### 4. Evaluate

```bash
python3 evaluate_heldout.py heldout/heldout_b101.json
```

This loads the trained model, predicts each held-out finding, compares against
the hand label, and writes `heldout_stats.md` with accuracy, precision,
recall, F1, a confusion matrix, and a per-rule breakdown that lists every
misclassified finding with the feature that drove the model's decision. The
report is organized by rule, so adding more rules later slots in cleanly.

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

## First result: B101 on Django

The first held-out evaluation used 32 hand-labeled B101 findings from Django
(20 true positives from production code, 12 false positives from real test
files). The model scored:

* **Accuracy: 27/32 (84%)**
* **Precision: 1.00**, so every time it said "true positive" it was right
* **Recall: 0.75**

All five errors were the same kind of case, and the report named the cause
directly: findings under `django/test/`, which is Django's testing *framework*
(production code that happens to live in a folder called `test`), not actual
tests. The `is_test_file` feature only checks whether "test" appears in the
path, so it fired on these and pushed the model to "false positive" (top
signal `is_test_file`, a strongly negative contribution). The reviewer labeled
them true positive, because they are production asserts that vanish under
`python -O` like any other.

This is the held-out set doing its job. The errors are not random: they expose
one precise, understandable limitation, that `is_test_file` cannot tell
`django/test/` (a production module) from `tests/` (real tests). That is a
real lead for improvement, and the kind of insight an explainable model gives
that a black-box classifier would not.

## Extending the evaluation

The same process applies to the other rules. Each new held-out set is a Bandit
report with hand-added labels under `heldout/`, and `evaluate_heldout.py`
already breaks results down per rule, so several rules can share one held-out
file or live in separate ones. Growing the held-out set to 30 to 50 findings
per rule makes the per-rule numbers steadier, since with a small sample a
single case moves the accuracy by several points.