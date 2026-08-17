# The taint engine

Design spec for the taint engine. The code is in `bandit_triage/taint.py`; the
tests check the behavior described here.

## Why it exists

Bandit flags an injection finding by matching the shape of the sink alone. It
does not check where the values came from or whether anything cleaned them,
because it analyzes each AST node in isolation. So two opposite cases get the
same treatment:

```python
# real injection: item comes from the URL
@app.route('/api/v1.0/storeAPI/<item>')
def searchAPI(item):
    curs = g.db.execute("SELECT * FROM shop_items WHERE name = '%s'" % item)

# safe: cache_key is an internal constant
cache_key = self.quote_name("cache_key")
return f"SELECT {cache_key} FROM %s ..."
```

Both are B608. The engine tells them apart.

## What it does

The engine is intra-procedural (one function, the same boundary Semgrep's free
tier draws). Flow across functions is left to heavier tools like CodeQL and
reported as unknown. It works backward from the sink in three steps:

1. **Find the variables in the sink.** For the first example above, `item`.
2. **Follow each variable back through the function** and classify its origin:
   an untrusted SOURCE (`request.*`, a route parameter, `input()`), a CONSTANT,
   a SANITIZER on the path, or a call it does not follow (UNKNOWN). Here `item`
   is bound by the `@app.route('.../<item>')` decorator, so it is an untrusted
   ROUTE_PARAM; `cache_key` traces to a string literal, so it is a CONSTANT.
3. **Build a dependency tree and produce a `TaintResult`:** whether an untrusted
   source reaches the sink, whether a sanitizer is on the path, the source kind,
   the path length, and whether the analysis was complete.

## When the source is UNKNOWN

UNKNOWN is the engine drawing its boundary honestly: it means "not determined
within this function", never a guess. It happens when a value comes from a call
the engine does not follow (`v = helper(x)`, inter-procedural), from a parameter
or global with no assignment in the function, or from an expression with no
local names left to trace. It differs from CONSTANT (proven safe) and from an
untrusted SOURCE (proven reachable), and it sets `analysis_complete` to False.

## What it does not do

The engine does not give the final verdict. It produces a `TaintResult` whose
fields become features for the classifier, which stays the decision maker:

```
Bandit finding -> taint engine -> TaintResult -> features -> ML -> verdict
```

This fills the data-flow gap while keeping the classifier explainable and the
analysis small and under the project's own control.

## Structures (`bandit_triage/taint.py`)

* `SourceType`: where a value comes from (REQUEST, ROUTE_PARAM, INPUT, NETWORK,
  CONSTANT, UNKNOWN); `is_untrusted` covers the attacker-controllable kinds.
* `NodeKind`: what a tree node is (VARIABLE, SOURCE, SANITIZER, CONSTANT, PARAM,
  SINK).
* `DepNode`: one node of the dependency tree, rooted at the sink. A tree, not a
  shared graph, so it is easy to walk and to render as an explanation.
* `RuleConfig`: per-rule sink names and sanitizers. Extending from B608 to
  B602/B703 means adding a config, not changing the analysis.
* `TaintResult`: the output; `likely_exploitable` is true when untrusted data
  reaches the sink with nothing cleaning it.

## Getting the function

The engine needs the whole function, but a finding carries only the flagged
line. `enclosing_function` reads the source file and extracts the narrowest
function around that line. To keep a dataset reproducible without the scanned
projects on disk, `embed_functions.py` bakes that function and the clean sink
line into the JSON (`function_code`, `sink_text`); the engine then reads them
directly. If neither is available, the feature falls back to the tainted-input
regex.

## Validation

Unit tests check each step on small functions from the held-out cases. The
end-to-end check wires the engine into the features and reruns
`evaluate_heldout.py`.

The B608 held-out was strengthened with real true positives from a vulnerable
Flask app (a keylogger backend whose endpoints paste `request` data into INSERT,
UPDATE, and SELECT queries), from 2 to 8 true positives; the engine recognizes
every one as exploitable. B608 now scores recall 0.88 and F1 0.78, and the whole
set reaches 58/63 (92%), F1 0.92.

The remaining errors are outside the data-flow gap and are noted honestly rather
than counted as engine failures: three static-template false positives (the
engine correctly stops calling them tainted, but they turn on Bandit's
confidence and on a `return f"..."` sink shape the engine does not yet cover),
and one login query where the engine finds the taint but marks the analysis
incomplete (a password passes through a hashing call), leaving the model just
below threshold.

As a final external check, Joern can be run once over the held-out cases as a
comparison baseline only, never inside the tool.