# The taint engine

The design specification for the taint engine. The code in
`bandit_triage/taint.py` implements the structures described here, and the tests
check the behavior described here.

## Why it exists

Bandit flags an injection finding (SQL, shell, XSS) by matching the shape of the
sink alone. It does not look at where the values came from, or whether anything
cleaned them first: it analyzes each AST node in isolation and does not follow
data flow. So two very different cases get the same treatment, and the
classifier, working only from Bandit's isolated view, cannot separate them
either.

A real SQL injection (`target_hackable/main.py:56`), where `item` comes from the
URL:

```python
@app.route('/api/v1.0/storeAPI/<item>', methods=['GET'])
def searchAPI(item):
    curs = g.db.execute("SELECT * FROM shop_items WHERE name = '%s'" % item)
```

A harmless static template (`operations.py:113`), where the value comes from an
internal constant:

```python
cache_key = self.quote_name("cache_key")
return f"SELECT {cache_key} FROM %s ORDER BY {cache_key} LIMIT 1 OFFSET %%s"
```

Both are B608. The engine adds the missing piece: it tells them apart.

## What it does

The engine is intra-procedural (a single function, the same boundary Semgrep's
free tier draws). Flow across functions and files is left to heavier tools like
CodeQL and reported honestly as unknown. It works backward from the sink in
three steps:

1. **Find the variables used in the sink.** For `main.py:56` the sink is
   `execute("..." % item)`, so the variable is `item`.
2. **Follow each variable backward through the function** to classify its
   origin: an untrusted SOURCE (`request.*`, a route parameter, `input()`), a
   CONSTANT (safe), a SANITIZER on the path, or a call it does not follow
   (marked UNKNOWN, analysis flagged incomplete). For `main.py:56`, `item` has
   no assignment but is a parameter, and the decorator
   `@app.route('.../<item>')` binds it from the URL, so it is a ROUTE_PARAM
   (untrusted). For `operations.py:113`, `cache_key` traces back to a string
   literal, so it is a CONSTANT (safe).
3. **Build the dependency tree and produce a `TaintResult`:** whether an
   untrusted source reaches the sink, whether a sanitizer sits on the path, the
   source kind, the path length, and whether the analysis was complete.

## What it does not do

The engine does not give the final true or false verdict. It produces a
`TaintResult` whose fields become features for the classifier, which stays the
decision maker:

```
Bandit finding -> taint engine -> TaintResult -> features -> ML -> verdict
```

This keeps the data-flow gap filled, the classifier explainable (now with better
signals than a surface regex), and the analysis small and under the project's
own control rather than delegated to a heavyweight engine.

## Structures (`bandit_triage/taint.py`)

* `SourceType`: where a value comes from (REQUEST, ROUTE_PARAM, INPUT, NETWORK,
  CONSTANT, UNKNOWN); `is_untrusted` is true for the attacker-controllable kinds.
* `NodeKind`: what a tree node represents (VARIABLE, SOURCE, SANITIZER, CONSTANT,
  PARAM, SINK).
* `DepNode`: one node of the dependency tree, rooted at the sink. Kept a tree,
  not a shared graph, so it stays easy to walk and to render as an explanation.
* `RuleConfig`: per-rule sanitizers (sources are shared across all injection
  rules). Extending from B608 to B602/B603/B703 means adding a config, not
  changing the analysis.
* `TaintResult`: the engine's output; `likely_exploitable` is true when
  untrusted data reaches the sink with nothing cleaning it on the way.

## Validation

Unit tests check each step on small functions taken from the held-out cases (the
route-parameter case recognizes an untrusted source, the static-template cases
recognize its absence). The end-to-end check reruns `evaluate_heldout.py` and
compares against the baseline in `heldout_stats.md`: the engine succeeds if the
four B608 errors there (three static-template false positives, one route-param
false negative) are corrected without breaking the true negatives. As a final
external check, Joern is run once over the held-out cases as a comparison
baseline only, never inside the tool.