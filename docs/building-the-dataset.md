# Building the dataset from real Bandit findings

How `data/labeled_findings.json` grows with real findings rather than only the
synthetic examples it started from.

## The idea

The model learns to imitate a reviewer's judgment: given a finding, is this
worth fixing (`true_positive`) or noise (`false_positive`)? That needs realistic
material, so instead of inventing examples we run Bandit on real projects and
label the output by hand.

## Sources

A useful dataset needs both sides of the judgment, and different repos supply
different sides:

* **Flask** (clean, well reviewed): almost all false positives (dummy passwords
  in tests, `SECRET_KEY: None` defaults). The noise side.
* **Bandit's own `examples/`**: written to trigger the rules, so the most
  authoritative true positives available.
* **Deliberately vulnerable apps** (Intentionally-Vulnerable-Python-Application,
  python-insecure-app): B105 true positives like a stored `admin`/`password123`
  pair. Each was still labeled by hand, not assumed true because the repo
  advertises itself as vulnerable.
* **Werkzeug**: B101 true positives, where `src/werkzeug/` uses `assert` for
  internal invariants that disappear under `python -O`.

Two sources were tried and dropped, worth recording: a repo keeping secrets in
`config.json` produced no B105 findings (Bandit reads only `.py`), and Bandit's
`examples/assert.py` held only `assert True`. Knowing which sources come up
empty is part of the process. And true positives from teaching repos are
realistic but deliberately planted; what matters is the shape (a realistic
value, in production code, used to authenticate).

## The process

1. **Clone a project**, a clean one for false positives and Bandit's `examples/`
   for true positives. Add cloned folders and reports to `.gitignore` (already
   covered: `target_*/`, `findings_*.txt`).
2. **Run Bandit** (`bandit -r target_flask -f json -o report.json`). Raw
   findings have no `label`: supplying that judgment is the whole job.
3. **Inspect one rule** with `inspect_findings.py report.json B105`, which writes
   a `findings_B105.txt` worksheet with a `LABEL: ____` line under each.
4. **Label by hand**, asking three questions rather than trusting severity: where
   is it (a `tests/` file leans false), what is the value (`"test"` leans false,
   `"sk_live_..."` leans true), and what the code does with it. Bandit rates
   plenty of false positives HIGH and real issues LOW.
5. **Add the findings** with `add_to_dataset.py report.json B105 false_positive
   1,3`, which copies them into the dataset and previews before writing.
6. **Register a new rule** by adding its ID to `KNOWN_TEST_IDS` in `features.py`.
7. **Retrain** with `dataset_stats.py`. Its accuracy is a training-data
   diagnostic; the real check is the held-out set (see `evaluation.md`).

## Worked example

A real B105 finding from Flask:

```
file:  target_flask/examples/tutorial/tests/test_auth.py  (line 13)
text:  Possible hardcoded password: 'a'
code:  response = client.post("/auth/register", data={"username": "a", "password": "a"})
```

A `tests/` file inside `examples/` (where), a single-character password (value),
simulating a registration to test a redirect (use). All three agree. Label:
`false_positive`.

## Rule notes

The dataset covers three rules. Other flow rules are set aside in
`data/archive/`; see "Archived rules" below.

**B105 (hardcoded_password_string).** Bandit flags string literals that look
like passwords. The signal is the value and its use: a placeholder or empty
default is false, a realistic secret used to authenticate is true. The
`secret_score` feature scores how secret-like the value looks; the variable name
alone does not settle it.

**B101 (assert_used).** Bandit flags every `assert`; they matter because
`python -O` strips them. The signal is location: an assert in a real test file
is routine (false), one in application code can vanish under `-O` (true).
`is_test_file` captures this, reading a file for a `TestCase` class or a `tests/`
path rather than trusting the word "test" anywhere (which would misread Django's
`django/test/` production package). Scanning all of Flask gave 1053 B101
findings, 1049 in test files and only 4 in `src/flask/`: real issues are rare
and the "where" question does almost all the work. Those 4 guard developer
invariants rather than security properties; we label them true for a consistent
policy, but keep the grey area deliberately, because cases like these make triage
a judgment rather than a lookup.

**B608 (hardcoded_sql_expressions).** Bandit flags SQL built with string
formatting. The signal is whether untrusted data reaches the query without
sanitization, which is what the taint engine determines (see `taint-engine.md`):
a query built from a route parameter or `request.*` is true, one from constants
or passed through parameterization is false.

## Archived rules

These rules were labeled and reasoned through, then set aside in
`data/archive/archived_findings.json` because they are flow rules waiting on the
taint engine (their label turns on the origin of the data, not on static
features). Their data and reasoning are kept so the work is not lost, and can be
reactivated by moving the examples back into `data/labeled_findings.json`.

**B301 (pickle), archived.** B301 flags use of `pickle` and its wrappers
(`dill`, `cPickle`, `jsonpickle`, `pandas.read_pickle`, `shelve`). Unpickling
executes arbitrary code in the byte stream, so `pickle.load()` on
attacker-controlled data is remote code execution (CWE-502, the same class as
B614's `torch.load()`). Always MEDIUM severity, HIGH confidence: Bandit is sure
it's a pickle call but can't see where the data came from.

The signal is the origin. An **untrusted source** is true: the stream comes from
outside the program (a request body, an uploaded file, a cookie, a socket, a
queue, a Redis cache), which is what the taint engine is meant to catch. A
**trusted source** is false: data the program produced itself (pickled and
unpickled in one scope, an internal cache file); the pattern is present but no
untrusted input reaches it.

Scanning Bandit's `examples/` produced 13 B301 findings, and every one
deserializes trusted data it generated itself (for instance dumping `[1, 2, '3']`
into an in-memory `io.BytesIO()` and loading it back), so all are false. The
label depends on context the flagged line doesn't show: `pickle.load(file_obj)`
looks identical whether `file_obj` is a trusted buffer or an attacker's upload,
so you have to trace where the data came from. This is precisely why B301 waits
on the engine. Because real projects rarely deserialize untrusted data (a well
known hazard), the true-positive side was filled with constructed examples of
documented unsafe patterns (`pickle.loads(request.data)`,
`pickle.load(uploaded_file)`), the same approach used for B105.

Other archived flow rules (B602 subprocess, B614 pytorch, B615 huggingface)
follow the same principle: their labels turn on the origin of the data, so they
wait until the taint engine reaches them.