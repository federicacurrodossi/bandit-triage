# Evaluating the model

How the model is tested on findings it was never trained on, to measure whether
it generalizes rather than memorizes.

## Why a held-out set is needed

`dataset_stats.py` reports accuracy on the same findings the model trained on: a
diagnostic, not a real evaluation, since a model can score well there just by
memorizing. A held-out set is findings from a project that contributed nothing
to training, hand-labeled with the same policy. Its accuracy is an honest
estimate of behavior on new code.

The held-out project must be one never trained on, so none of the training
sources qualify. **Django** was used: large and mature, sharing no findings with
the training set, and big enough to yield meaningful per-rule counts. There is
no public dataset of labeled Bandit findings, so the held-out set is built the
same way the training set is: scan a real project, then label by hand.

## The process

**1. Scan a fresh project.**

```bash
git clone --depth 1 https://github.com/django/django.git target_django
bandit -r target_django -f json -o django_findings.json
```

`target_django/` and the report are regenerated on demand, so they are
gitignored.

**2. Split the report by rule** with `split_findings_by_rule.py
django_findings.json django_findings/`, so each rule can be labeled on its own.

**3. Label a sample by hand, before running the model.** A large project has too
many findings to label all (Django has 70 B101), so a representative sample per
rule is taken, covering both labels, using the same three-question policy as the
training data. Labeling *before* seeing predictions keeps the test independent.
Labels go in a **spec file**, one finding per line as
`<label> <path-substring>:<line>`; `#` starts a comment:

```
false_positive core/cache/backends/db.py:136
true_positive  main.py:25
```

**4. Build the held-out file.** Each rule keeps **one** spec holding every case
for that rule, whatever project it came from. `build_heldout.py` takes that spec
plus **all** the reports the findings live in, matches each line by path and
line, copies the finding verbatim, attaches the label, and writes the file:

```bash
python3 build_heldout.py b608_spec.txt heldout/heldout_b608.json \
    django_findings/B608.json hackable_findings.json
```

Adding a project later means adding its lines to the spec and its report to the
command. Held-out files are grouped one per rule and, unlike the raw scans, are
committed: they are hand-made test data like `data/labeled_findings.json`.

Why several sources: a clean framework like Django gives plenty of *false*
positives (its ORM builds SQL from internal identifiers, flagged but safe) but
no *true* positives, since a mature project has no real injection. The true
positives come from deliberately vulnerable apps (for B608, two small Flask apps
whose endpoints paste `request` data into queries). Each is traceable to the
real file it came from, so the set is auditable rather than synthetic.

**5. Evaluate the whole folder** with `evaluate_heldout.py heldout/`, which runs
every rule file at once (so fixing one rule but breaking another is caught
immediately), and writes `heldout_stats.md` with accuracy, precision, recall,
F1, a confusion matrix, and every misclassified finding with the feature that
drove the decision.

## What the numbers mean

* **Accuracy**: share of findings labeled the way the reviewer did.
* **Precision** (true-positive class): how often the model is right when it says
  "true positive". High precision means few false alarms.
* **Recall**: how many real true positives it caught.
* **F1**: precision and recall in one number.

Because the model is explainable, each misclassified finding names the feature
that pushed it wrong, so every error points at a fixable cause.

## Worked example: B101 on Django

The first evaluation used 32 hand-labeled B101 findings (20 true positives from
production code, 12 false positives from real test files). The model scored
27/32 (84%), and all five errors were the same case: findings under
`django/test/`, Django's testing *framework* (production code in a folder called
`test`), not actual tests. The old `is_test_file` only checked for "test" in the
path, so it fired on these and pushed the model to "false positive"; the reviewer
labeled them true positive, because they are production asserts that vanish under
`python -O`.

The fix followed the lead: `is_test_file` now reads the file for a `TestCase`
class, or accepts a `tests/` directory or `test_*.py` name, telling
`django/test/` apart from real tests. B101 recall rose from 0.75 to 1.00 and its
accuracy to 31/32 (97%), and the whole held-out set now sits at 58/63 (92%), F1
0.92. This is the kind of concrete, fixable insight an explainable model gives
that a black box would not.

## Extending the evaluation

Adding a rule is the same five steps. Adding a *new source* to an existing rule
is smaller: add the cases to that rule's spec, add the report to the build
command, rebuild. Growing each rule's set to 30 to 50 findings makes its numbers
steadier (with a small sample one case moves accuracy several points), and
pulling cases from more than one project shows the model generalizing across
codebases rather than fitting one.