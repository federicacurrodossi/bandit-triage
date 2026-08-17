"""Bake the enclosing function and clean sink line into a findings JSON.

The taint engine needs the whole function that contains a finding, but a Bandit
report only carries the flagged line. This utility reads each finding's source
file once, extracts the enclosing function and the clean sink line, and writes
them back into the JSON as `function_code` and `sink_text`.

Run it once, locally, where the scanned projects are present. After that the
dataset is self-contained: the engine reads the baked-in context and no longer
needs the source files, so the evaluation is reproducible anywhere.

Usage:
    python3 embed_functions.py data/labeled_findings.json
    python3 embed_functions.py heldout/heldout_b608.json

Only findings whose rule has an engine config (today B608) are enriched; others
are left untouched. Findings whose source file is missing are skipped and
reported, so you can see exactly what was and was not baked in.
"""
import json
import sys

from bandit_triage.taint import enclosing_function, sink_line

# Rules the engine analyzes. Keep in sync with features._RULE_CONFIGS.
ENGINE_RULES = {"B608"}


def _find_list(data):
    """Return (container, key) for the list of findings, supporting both the
    {"findings": [...]} training shape and the {"results": [...]} report shape.
    """
    if isinstance(data, list):
        return data, None
    for key in ("findings", "results"):
        if isinstance(data.get(key), list):
            return data[key], key
    raise ValueError("no findings list found in JSON")


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    path = sys.argv[1]

    with open(path) as f:
        data = json.load(f)
    findings, _ = _find_list(data)

    enriched = skipped = untouched = 0
    for it in findings:
        if it.get("test_id") not in ENGINE_RULES:
            untouched += 1
            continue
        filename = it.get("filename")
        line = it.get("line_number", 0)
        func = enclosing_function(filename, line)
        if func is None:
            skipped += 1
            print(f"  skip (source unavailable): {filename}:{line}")
            continue
        it["function_code"] = func
        it["sink_text"] = sink_line(filename, line) or it.get("code", "")
        enriched += 1

    with open(path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\nDone: {enriched} enriched, {skipped} skipped, {untouched} left "
          f"untouched (non-engine rules).")
    print(f"Written back to {path}")


if __name__ == "__main__":
    main()