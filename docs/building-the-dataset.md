# Building the dataset from real Bandit findings

How `data/labeled_findings.json` grows with real findings rather than only the
synthetic examples it started from.

## The idea

The model learns to imitate a reviewer's judgment: given a finding, is this
worth fixing (`true_positive`) or noise that can be ignored
(`false_positive`)? Learning that needs realistic material, so instead of
inventing examples we run Bandit on real open source projects and label the
output by hand.

## Sources

A useful dataset needs both sides of the judgment, and different repos supply
different sides.

* **Flask** (`github.com/pallets/flask`) is mature and well reviewed, so nearly
  everything it produces is a false positive: dummy passwords in tests,
  `SECRET_KEY: None` defaults, placeholder values. A clean project has no real
  secrets sitting in code. This is the noise side.
* **Bandit's own `examples/`** (`github.com/PyCQA/bandit`) are files written
  deliberately to trigger the rules, which makes them the most authoritative
  true positives available. For B105 they contain realistic hardcoded secret
  patterns that a clean project like Flask simply doesn't have.
* **Intentionally-Vulnerable-Python-Application**
  (`github.com/mukxl/Intentionally-Vulnerable-Python-Application`) is a
  teaching repo whose `admin` / `password123` pair is a clear B105 true
  positive: a stored authentication credential in application code, not test
  code. It was still labeled by hand under the policy below, not assumed true
  because the repo advertises itself as vulnerable.
* **python-insecure-app** (`github.com/trottomv/python-insecure-app`) is a
  deliberately vulnerable FastAPI app. It gave one true positive
  (`SUPER_SECRET_TOKEN = "5u93R53Cr3tT0k3n"`, a realistic token in config) and
  two false positives (`SUPER_SECRET_NAME = "John Ripper"`, a joke value, once
  in config and once in a test). Good evidence that the variable name alone
  doesn't settle the label; the value and the context do.
* **Werkzeug** (`github.com/pallets/werkzeug`), the WSGI library Flask is built
  on, supplies B101 true positives. Its `src/werkzeug/` uses `assert` for
  internal invariants: type checks (`assert isinstance(env, dict)`),
  preconditions (`assert self.map is not None`), call order guards. These are
  real asserts in production code that disappear under `python -O`, which is
  exactly what B101 warns about. Large mature frameworks are the natural home
  for them, since small demo repos rarely assert outside tests.

Two sources were tried and dropped. `flask_config_example` produced no B105
findings at all, because it keeps secrets in a `config.json` and Bandit only
reads `.py` files. Bandit's own `examples/assert.py` held nothing but
`assert True`, technically flagged but uninstructive since it protects nothing,
so Werkzeug's real asserts were used instead. Both are recorded here because
knowing which sources come up empty, and why, is part of the process.

Training on Flask alone would teach the model only what noise looks like.
Pairing it with intentional examples gives it both sides, which is what it
needs to tell them apart.

**On true positives:** examples taken from vulnerable or teaching repos are
realistic but deliberately planted, and that's expected. A genuinely leaked
production secret is rare and hard to come by, for good reason. What matters is
that an example has the right shape: a realistic value, in production code,
actually used to authenticate. This is stated openly rather than presented as
scraped real world leaks.

## The process

### 1. Clone a project to scan

```bash
# a clean project (mostly false positives)
git clone --depth 1 https://github.com/pallets/flask.git target_flask

# Bandit's intentional examples (a good source of true positives)
git clone --depth 1 https://github.com/PyCQA/bandit.git target_bandit
```

Add the cloned folders and generated reports to `.gitignore` so they never
reach your own repo. The current `.gitignore` already covers `target_*/`,
`findings_*.txt`, and the named report files.

### 2. Run Bandit and save the JSON

```bash
bandit -r target_flask -f json -o real_findings.json
bandit -r target_bandit/examples -f json -o bandit_examples.json
```

These are raw findings, exactly as Bandit reports them. Note there is no
`label` field: Bandit flags patterns but never judges whether they matter in
context. Supplying that judgment is the whole job here.

### 3. Inspect one rule at a time

All findings at once is overwhelming, since Flask alone produces over a
thousand. Start with the per rule summary, then open a single rule:

```bash
python3 inspect_findings.py real_findings.json
python3 inspect_findings.py real_findings.json B105
```

The second command prints each finding and writes a worksheet
(`findings_B105.txt`) with a `LABEL: ____` line under each one to fill in.

### 4. Label by hand

For each finding, choose `true_positive` or `false_positive` by asking three
questions about the context rather than trusting Bandit's severity:

1. **Where is it?** A file under `tests/` or `examples/` leans false positive.
2. **What is the value?** An obviously fake value (`"a"`, `"test"`,
   `"changeme"`) leans false positive; something realistic (`"sk_live_..."`,
   `"pr0d-p@ssw0rd"`) leans true positive.
3. **What does the code do with it?** Filling a test form is harmless.
   Authenticating to a production database is not.

Severity is one clue, not the answer. Bandit rates plenty of things HIGH that
are false positives, such as `shell=True` on a fixed command, and LOW on things
that are real, such as a production API key it underestimates.

### 5. Add the labeled findings

`add_to_dataset.py` copies findings straight from a report into the dataset in
the right format, so no JSON editing by hand. Give it the report, the rule, the
label, and the finding numbers that `inspect_findings.py` printed:

```bash
python3 add_to_dataset.py insecure_app_findings.json B105 false_positive 1,3
python3 add_to_dataset.py insecure_app_findings.json B105 true_positive 2
```

It previews the findings and asks for confirmation before writing.

### 6. Register a new rule type

If the rule is new to the model, add its ID to `KNOWN_TEST_IDS` in
`bandit_triage/features.py` so it gets a feature.

### 7. Retrain and check balance

```bash
python3 dataset_stats.py
```

This retrains, saves `model.json`, and reports counts per rule plus a hint
about which rules still need examples. The accuracy figure is measured on the
same data the model trained on, so read it as a diagnostic. A real evaluation
would need a separate test set.

## Worked example

A real B105 finding from Flask:

```
file:  target_flask/examples/tutorial/tests/test_auth.py  (line 13)
severity: LOW | confidence: MEDIUM
text:  Possible hardcoded password: 'a'
code:
    13   response = client.post("/auth/register", data={"username": "a", "password": "a"})
```

It sits in a `tests/` file inside `examples/` (question 1), the password is a
single character (question 2), and the code only simulates a registration to
test a redirect (question 3). All three agree.

**Label: `false_positive`.**

## Constructed true positives for B105

Real hardcoded secrets are scarce in clean open source projects, so this class
was hard to fill from real repos alone. To balance it, a few examples were
constructed using publicly documented secret formats, never values invented at
random and never anyone's actual leaked secret. They live in
`constructed_examples/constructed_secrets_example.py`.

Where the patterns come from:

* **AWS secret access key**, the 40 character `[A-Za-z0-9/+=]{40}` format,
  using AWS's own public example value `wJalrXUtnFEMI/...EXAMPLEKEY` (note the
  literal word EXAMPLE). From AWS Secrets Manager and CloudFormation docs, and
  the Cencori secrets detection pattern list.
* **JWT signing secret**, the `eyJhbGci...` base64 header shape every HS256 JWT
  opens with. From the Cencori list and AWS Kendra docs.
* **MongoDB connection string**, `mongodb+srv://user:pass@cluster...` with an
  embedded password. From the Cencori list.
* **Stripe API key**, the `sk_test_[0-9a-zA-Z]{24,}` format, using Stripe's
  public documentation test key.
* **SMTP password**, a generic complex password mixing case, digits, and
  symbols, matching the generic `(password|passwd|pwd)` pattern.

Why they're built this way:

* **Five different shapes**, a cloud key, a token, a connection string, an API
  key, and a password. This teaches the model that a true positive comes in
  many forms, so it generalizes better than it would from five nearly identical
  passwords.
* **All in production files and all actually used**, each passed to something
  that consumes it (`boto3.Session`, `jwt.encode`, `MongoClient`,
  `stripe.api_key`, `smtp.login`), so the context reads as a live credential
  rather than a dead placeholder.
* **Documented public example values**, giving them the length and character
  variety of real secrets, so they score high on `secret_score` without being
  anyone's real secret.

One quirk worth knowing: B105 only fires when the string is tied to a name
containing `password`, `pass`, `passwd`, `pwd`, `secret`, `token`, or
`secrete`. So Bandit catches `AWS_SECRET_ACCESS_KEY`, `JWT_SECRET`, and
`SMTP_PASSWORD`, but misses `STRIPE_API_KEY` and `DATABASE_URL` even though
they're just as real. That gap is useful: both misses were added to the dataset
by hand so the triage model learns to spot them by value and context. A small
demonstration that the triage layer can reason past Bandit's pattern matching.

## Rule notes: B101 (assert_used)

B101 flags every use of `assert`. It matters because asserts are stripped when
Python compiles to optimized bytecode (`python -O`), so any check written as an
assert silently vanishes in that mode. Bandit's advice is to raise a real error
instead. B101 is always LOW severity and HIGH confidence: Bandit is certain
it's an assert, it just can't know whether it matters.

The signal here is almost the mirror of B105's, and it turns on location:

* **Assert in a test file** is a `false_positive`. Using `assert` in unit tests
  is the normal way to check results, and Bandit's own config suggests skipping
  the rule there. The `is_test_file` feature captures this directly.
* **Assert in application code** is a `true_positive`. It could vanish under
  `python -O`, so by the rule it should be a real error.

Scanning all of Flask produced **1053** B101 findings, of which **1049** were
in test files and only **4** in `src/flask/` (`assert view_func is not None` in
`scaffold.py`, `assert meth is not None` in `views.py`). That lopsided split is
itself the lesson: for B101 real issues are rare and the "where" question does
almost all the work.

An honest caveat: those 4 are true positives by the rule, but in practice they
guard developer side invariants rather than security critical protections. A
strict reviewer labels them true positive on principle; a pragmatic one might
call them low risk defensive checks. We label them `true_positive` for a
consistent policy, but the ambiguity is kept deliberately, because grey cases
like these are what make triage a judgment rather than a lookup.

## Rule notes: B301 (pickle)

B301 flags use of `pickle` and its wrappers (`dill`, `cPickle`, `jsonpickle`,
`pandas.read_pickle`, `shelve`) to deserialize data. Unpickling executes
arbitrary code embedded in the byte stream, so `pickle.load()` on data an
attacker controls is remote code execution. Same vulnerability class (CWE-502)
as the `torch.load()` check in B614. Always MEDIUM severity, HIGH confidence:
Bandit is sure it's a pickle call but can't see where the data came from.

The signal is the origin of the data:

* **Untrusted source** is a `true_positive`. The stream comes from outside the
  program's control: a request body, an uploaded file, a cookie, a socket, a
  message queue, a Redis cache. The risk is real, and this is what
  `has_tainted_input` exists to catch.
* **Trusted source** is a `false_positive`. The stream is data the program
  produced itself: a value pickled and unpickled in one scope, an internal
  cache file, a fixed local artifact. The pattern is present but there's no
  untrusted input.

Scanning Bandit's `examples/` produced 13 B301 findings across `pickle`,
`dill`, `jsonpickle`, `pandas`, and `shelve`. Reading the surrounding code,
every one deserializes trusted data it generated itself. `pickle_deserialize.py`
dumps `[1, 2, '3']` into an in memory `io.BytesIO()` buffer and loads it back a
few lines later. Even the cases that appear to read from a file object are
reading a buffer the same script just wrote. They exist to check that Bandit
detects the pattern, not to represent attacks, so they're all false positives.

The label depends on context the flagged line doesn't show:
`pickle.load(file_obj)` looks identical whether `file_obj` is a trusted buffer
or an attacker's upload. You have to trace where the data came from.

A consequence for dataset building: real projects are a good source of B301
false positives, but genuine true positives are rare in scanned code, precisely
because deserializing untrusted data is a well known hazard that careful
projects avoid. The true positive side is therefore filled with constructed
examples based on documented unsafe patterns (`pickle.loads(request.data)`,
`pickle.load(uploaded_file)`, `pickle.loads(base64.b64decode(cookie))`), the
same approach used for B105.

## Rule notes: B608 (hardcoded_sql_expressions)

B608 flags SQL queries built by string operations (`%`, `+`, `.format()`,
f-strings, `.replace()`), the classic path to SQL injection (CWE-89). Unlike
the earlier rules, confidence carries information here: a bare suspicious
string is LOW, but a string passed to a DBAPI `execute` call is raised to
MEDIUM, since it is more clearly a real query being run.

The signal is the origin of the value pasted into the query:

* **Untrusted input concatenated into the query** is a `true_positive`. A
  request parameter or other outside value is pasted into the SQL text. This is
  `has_dynamic_concat` (the string is built, not a literal) and
  `has_tainted_input` (the value is untrusted) firing together.
* **Fully internal queries** are a `false_positive`. The query is built with a
  dynamic form Bandit flags, but every interpolated piece is a fixed internal
  value (a hardcoded table name, an internal constant, a value already coerced
  to `int`), so nothing an attacker controls reaches the query. Calling this
  noise is what the triage layer adds.

The line between the two is the origin of the interpolated value, not the form:

```python
name = request.args["name"]
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")   # true positive
cursor.execute(f"SELECT * FROM {TABLE_NAME} ORDER BY id")      # false positive
```

Both are f-strings that Bandit flags identically. The first pastes in an
untrusted request value; the second only interpolates an internal constant. You
can't judge B608 from the flagged line alone.

Both sides of this rule are constructed, for different reasons. Bandit's
`examples/` directory is the richest single source for B608 (49 findings), but
every one interpolates an abstract `identifier` whose origin is never shown, so
the form is all Bandit already detects and there are no false positives among
them. So the true positive side is built with real context, the interpolated
value coming visibly from `request` (query params, form fields, a JSON body, a
cookie, a path parameter), across all the flagged forms. The false positive
side is built too, and here a detail surfaced: properly parameterized queries
(`execute("... = ?", (val,))`) are not flagged by Bandit at all, because
nothing is concatenated, so they can't serve as findings. The false positives
therefore use the one shape that is flagged yet safe: a dynamic query whose
interpolated pieces are all internal constants.