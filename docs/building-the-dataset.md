# Building the dataset from real Bandit findings

How `data/labeled_findings.json` grows with real findings rather than only the
synthetic examples it started from.

## The idea

The model learns to imitate a reviewer's judgment: given a finding, is this
worth fixing (`true_positive`) or noise that can be ignored (`false_positive`)?
That needs realistic material, so instead of inventing examples we run Bandit on
real open source projects and label the output by hand.

## Sources

A useful dataset needs both sides of the judgment, and different repos supply
different sides.

* **Flask** (clean, well reviewed) is almost all false positives: dummy
  passwords in tests, `SECRET_KEY: None` defaults, placeholders. The noise side.
* **Bandit's own `examples/`** are written deliberately to trigger the rules,
  so they are the most authoritative true positives available (realistic
  hardcoded secret patterns a clean project lacks).
* **Deliberately vulnerable apps** (Intentionally-Vulnerable-Python-Application,
  python-insecure-app) supply B105 true positives like a stored
  `admin`/`password123` pair or a realistic token in config. Each was still
  labeled by hand under the policy below, not assumed true because the repo
  advertises itself as vulnerable.
* **Werkzeug** supplies B101 true positives: `src/werkzeug/` uses `assert` for
  internal invariants (type checks, preconditions) that disappear under
  `python -O`. Large mature frameworks are the natural home for these, since
  small demo repos rarely assert outside tests.

Two sources were tried and dropped, and that is worth recording: a repo keeping
secrets in `config.json` produced no B105 findings (Bandit reads only `.py`),
and Bandit's `examples/assert.py` held nothing but `assert True`, flagged but
uninstructive. Knowing which sources come up empty, and why, is part of the
process.

On true positives: examples from vulnerable or teaching repos are realistic but
deliberately planted, which is expected (a genuinely leaked production secret is
rare, for good reason). What matters is the shape: a realistic value, in
production code, actually used to authenticate.

## The process

1. **Clone a project to scan**, a clean one for false positives and Bandit's
   `examples/` for true positives. Add the cloned folders and generated reports
   to `.gitignore` (already covered: `target_*/`, `findings_*.txt`, the report
   files) so they never reach your own repo.

2. **Run Bandit and save the JSON** (`bandit -r target_flask -f json -o
   report.json`). These are raw findings, with no `label` field: Bandit flags
   patterns but never judges whether they matter. Supplying that judgment is the
   whole job.

3. **Inspect one rule at a time** with `inspect_findings.py report.json B105`,
   which prints each finding and writes a `findings_B105.txt` worksheet with a
   `LABEL: ____` line under each.

4. **Label by hand**, asking three questions about context rather than trusting
   Bandit's severity: where is it (a file under `tests/` leans false positive),
   what is the value (a fake `"test"` leans false, a realistic `"sk_live_..."`
   leans true), and what the code does with it (filling a test form is harmless,
   authenticating to a production database is not). Bandit rates plenty of false
   positives HIGH and real issues LOW, so severity is one clue, not the answer.

5. **Add the labeled findings** with `add_to_dataset.py report.json B105
   false_positive 1,3`, which copies them into the dataset in the right format
   and previews before writing (no JSON editing by hand).

6. **Register a new rule** by adding its ID to `KNOWN_TEST_IDS` in
   `bandit_triage/features.py` so it gets a feature.

7. **Retrain and check balance** with `dataset_stats.py`, which retrains, saves
   `model.json`, and reports counts per rule. Its accuracy is measured on the
   training data, so read it as a diagnostic; the real check is the held-out set
   (see `evaluation.md`).

## Worked example

A real B105 finding from Flask:

```
file:  target_flask/examples/tutorial/tests/test_auth.py  (line 13)
severity: LOW | confidence: MEDIUM
text:  Possible hardcoded password: 'a'
code:  response = client.post("/auth/register", data={"username": "a", "password": "a"})
```

It sits in a `tests/` file inside `examples/` (where), the password is a single
character (value), and the code only simulates a registration to test a redirect
(use). All three agree. Label: `false_positive`.

## Rule notes

The dataset currently covers three rules. Other flow rules (B301 pickle, B602
subprocess, and so on) are set aside in `data/archive/` until the taint engine
covers them; their notes and reasoning are kept under "Archived rules" below.

**B105 (hardcoded_password_string).** Bandit flags string literals that look
like passwords. The signal is the value and its use: a placeholder or empty
default is a false positive, a realistic secret used to authenticate is a true
positive. The `secret_score` feature scores how secret-like the value looks;
the variable name alone does not settle it.

**B101 (assert_used).** Bandit flags every `assert`; they matter because
`python -O` strips them. Always LOW severity, HIGH confidence. The signal turns
on location: an assert in a real test file is the normal way to check results
(false positive), while an assert in application code can vanish under `-O`
(true positive). `is_test_file` captures this, reading a file for a `TestCase`
class or a `tests/` path rather than trusting the word "test" anywhere in the
path (which would misread Django's `django/test/` production package). Scanning
all of Flask gave 1053 B101 findings, 1049 in test files and only 4 in
`src/flask/`: for B101, real issues are rare and the "where" question does
almost all the work. Those 4 guard developer invariants rather than security
properties; we label them `true_positive` for a consistent policy, but the grey
area is kept deliberately, because cases like these are what make triage a
judgment rather than a lookup.

**B608 (hardcoded_sql_expressions).** Bandit flags SQL built with string
formatting. The signal is whether untrusted data reaches the query without
sanitization, which is exactly what the taint engine determines (see
`taint-engine.md`): a query built from a route parameter or `request.*` is a
true positive, one built from constants or passed through parameterization is a
false positive.

## Archived rules

These rules were labeled and reasoned through, then set aside in
`data/archive/archived_findings.json` because they are flow rules waiting on the
taint engine to cover them (their true positive or false positive split turns on
the origin of the data, not on static features). Their data and reasoning are
kept here so the work is not lost and can be reactivated by moving the examples
back into `data/labeled_findings.json` once the engine handles them.

**B301 (pickle), archived.** B301 flags use of `pickle` and its wrappers
(`dill`, `cPickle`, `jsonpickle`, `pandas.read_pickle`, `shelve`) to deserialize
data. Unpickling executes arbitrary code embedded in the byte stream, so
`pickle.load()` on data an attacker controls is remote code execution (CWE-502,
the same class as the `torch.load()` check in B614). Always MEDIUM severity,
HIGH confidence: Bandit is sure it's a pickle call but can't see where the data
came from.

The signal is the origin of the data. An **untrusted source** is a
`true_positive`: the stream comes from outside the program (a request body, an
uploaded file, a cookie, a socket, a queue, a Redis cache), which is exactly
what the taint engine is meant to catch. A **trusted source** is a
`false_positive`: data the program produced itself (a value pickled and
unpickled in one scope, an internal cache file, a fixed local artifact); the
pattern is present but no untrusted input reaches it.

Scanning Bandit's `examples/` produced 13 B301 findings across `pickle`, `dill`,
`jsonpickle`, `pandas`, and `shelve`. Reading the surrounding code, every one
deserializes trusted data it generated itself (for instance dumping `[1, 2, '3']`
into an in-memory `io.BytesIO()` buffer and loading it back a few lines later),
so they are all false positives. The label depends on context the flagged line
does not show: `pickle.load(file_obj)` looks identical whether `file_obj` is a
trusted buffer or an attacker's upload, so you have to trace where the data came
from. This is precisely why B301 waits on the engine.

A consequence for dataset building: real projects are a good source of B301
false positives, but genuine true positives are rare in scanned code, precisely
because deserializing untrusted data is a well known hazard that careful
projects avoid. The true positive side was therefore filled with constructed
examples based on documented unsafe patterns (`pickle.loads(request.data)`,
`pickle.load(uploaded_file)`, `pickle.loads(base64.b64decode(cookie))`), the
same approach used for B105.

Other archived flow rules (B602 subprocess, B614 pytorch, B615 huggingface)
follow the same principle: their labels turn on the origin of the data, so they
wait in the archive until the taint engine reaches them.