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

## When the source is UNKNOWN

UNKNOWN is not a failure, it is the engine drawing its own boundary honestly.
The engine is intra-procedural, so whenever a value's origin cannot be settled
without leaving the function, it stops and reports UNKNOWN rather than guessing.
This happens in three situations, all of which mean "the answer lies outside
what this engine promises to analyze":

1. **A value from a call the engine does not follow.** When a variable is
   assigned from a plain function call that is not a known sanitizer, such as
   `v = compute_something(x)`, the engine does not descend into
   `compute_something`: that is inter-procedural, the territory left to heavier
   tools. The origin is marked UNKNOWN and the analysis is flagged incomplete.

2. **A name with no assignment in the function that is not a route parameter.**
   If a variable is never assigned inside the function and is not bound from a
   route (so it is an ordinary parameter passed by some caller, or a module
   global), its value arrives from outside the function. The engine cannot see
   that far, so it reports UNKNOWN.

3. **A value the engine cannot decompose into names to follow.** If the right
   hand side is neither a recognized source, nor a constant, nor a sanitizer,
   nor something built out of other local variables (for example an attribute
   access on an object the engine knows nothing about), there is nothing left
   to trace, and the origin stays UNKNOWN.

The distinction matters for how the result is read. UNKNOWN is different from
CONSTANT (proven safe) and different from an untrusted SOURCE (proven
attacker-reachable). It is an explicit "not determined within the function",
which is exactly the honest signal an inter-procedural case should produce, and
it is why `TaintResult.analysis_complete` is set to False whenever an UNKNOWN
node appears in the tree.

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
* `RuleConfig`: per-rule sink names and sanitizers (sources are shared across
  all injection rules). Extending from B608 to B602/B603/B703 means adding a
  config, not changing the analysis.
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