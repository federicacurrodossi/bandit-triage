"""
Build a labeled held-out set from one spec and one or more real Bandit reports.

The workflow is: keep ONE spec file per rule (for example b608_spec.txt). Each
line is a hand-chosen label plus a locator:

    <label> <path-substring>:<line_number>

for example:

    false_positive core/cache/backends/db.py:136
    true_positive  main.py:25

When you find new cases for the rule in a different project, you just add lines
to the SAME spec, and pass that project's Bandit report alongside the others.
The script searches every report you give it, finds each finding by path and
line, copies it verbatim (real code, confidence, line numbers, not retyped),
attaches your label, and writes the held-out file.

Lines starting with # are comments. The path only has to be a unique substring
of a finding's filename across all the reports, so you don't type full paths.

Usage:
    python3 build_heldout.py <spec.txt> <output.json> <report1.json> [report2.json ...]

Example (one spec, two source projects):
    python3 build_heldout.py b608_spec.txt heldout/heldout_b608.json \
        django_findings/B608.json hackable_findings.json
"""
import argparse
import json
from pathlib import Path


def main():
    ap = argparse.ArgumentParser(
        description="Build a held-out set from one spec and several Bandit reports.")
    ap.add_argument("spec", help="spec file: '<label> <path-substring>:<line>' per line")
    ap.add_argument("output", help="held-out file to write")
    ap.add_argument("reports", nargs="+",
                    help="one or more Bandit reports to pull the real findings from")
    args = ap.parse_args()

    # load every report and pool all findings together
    all_findings = []
    for rp in args.reports:
        if not Path(rp).exists():
            print(f"skipping missing report: {rp}")
            continue
        with open(rp) as f:
            all_findings.extend(json.load(f).get("results", []))

    if not all_findings:
        print("No findings loaded from the given reports.")
        return

    # parse the spec into (label, path_substring, line_number) rows
    selections = []
    with open(args.spec) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                label, locator = line.split(None, 1)
                path_part, lineno = locator.rsplit(":", 1)
                lineno = int(lineno)
            except ValueError:
                print(f"skipping malformed spec line: {line!r}")
                continue
            if label not in ("true_positive", "false_positive"):
                print(f"skipping line with bad label: {line!r}")
                continue
            selections.append((label, path_part.strip(), lineno))

    picked = []
    missing = []
    for label, path_part, lineno in selections:
        matches = [
            fnd for fnd in all_findings
            if path_part in fnd["filename"] and fnd.get("line_number") == lineno
        ]
        if len(matches) == 1:
            finding = dict(matches[0])
            finding["label"] = label
            picked.append(finding)
        elif not matches:
            missing.append((path_part, lineno, "no match in any report"))
        else:
            missing.append((path_part, lineno, f"{len(matches)} matches, be more specific"))

    if missing:
        print("Could not uniquely resolve these selections:")
        for path_part, lineno, why in missing:
            print(f"  {path_part}:{lineno}  ({why})")
        print()

    if not picked:
        print("No findings selected; nothing written.")
        return

    base = {"errors": [], "generated_at": "", "metrics": {}, "results": picked}
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(base, f, indent=2)

    t = sum(1 for p in picked if p["label"] == "true_positive")
    fp = len(picked) - t
    print(f"Wrote {args.output}: {len(picked)} findings ({t} true, {fp} false)")
    if missing:
        print(f"  ({len(missing)} selection(s) unresolved, see above)")


if __name__ == "__main__":
    main()