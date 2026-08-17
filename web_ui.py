"""
A very small local web UI for bandit-triage.

Run it with:
    python3 web_ui.py
then open http://127.0.0.1:5001 in your browser.

Paste a Bandit JSON report (from `bandit -r . -f json`) into the box, or
click "Load example" to use the bundled sample, and it renders the triaged,
explained results visually instead of as terminal text.

The HTML lives in templates/index.html and the styling in static/style.css,
following Flask's standard layout.
"""
import json

from flask import Flask, render_template, request

from bandit_triage.classifier import TriageClassifier
from bandit_triage.features import extract_features
from bandit_triage.loader import Finding, _extract_cwe
from bandit_triage.cli import describe_contribution, pick_top_reason

app = Flask(__name__)

MODEL_PATH = "model.json"
SAMPLE_PATH = "data/sample_bandit_report.json"


def triage_report(report_data: dict):
    """Takes parsed Bandit JSON, returns a list of (finding, prediction) sorted
    by priority. Mirrors the CLI logic so the UI and CLI stay consistent."""
    model = TriageClassifier.load(MODEL_PATH)

    findings = []
    for item in report_data.get("results", []):
        cwe_id, cwe_link = _extract_cwe(item)
        findings.append(
            Finding(
                filename=item["filename"],
                code=item.get("code", ""),
                issue_confidence=item.get("issue_confidence", "MEDIUM"),
                issue_severity=item.get("issue_severity", "MEDIUM"),
                issue_text=item.get("issue_text", ""),
                line_number=item.get("line_number", 0),
                test_id=item.get("test_id", ""),
                test_name=item.get("test_name", ""),
                cwe_id=cwe_id,
                cwe_link=cwe_link,
                function_code=item.get("function_code"),
                sink_text=item.get("sink_text"),
            )
        )

    scored = []
    for f in findings:
        pred = model.predict(extract_features(f))
        top = pick_top_reason(f, pred)
        scored.append({
            "filename": f.filename,
            "line_number": f.line_number,
            "test_id": f.test_id,
            "test_name": f.test_name,
            "issue_text": f.issue_text,
            "code": f.code,
            "cwe_id": f.cwe_id,
            "cwe_link": f.cwe_link,
            "bandit_severity": f.issue_severity,
            "label": pred.label,
            "prob": pred.true_positive_probability,
            "reason": describe_contribution(top),
        })

    scored.sort(key=lambda s: s["prob"], reverse=True)
    return scored


@app.route("/", methods=["GET", "POST"])
def index():
    report_text = ""
    results = None
    error = None

    if request.method == "POST":
        if request.form.get("load_example"):
            with open(SAMPLE_PATH) as f:
                report_text = f.read()
            report_data = json.loads(report_text)
            results = triage_report(report_data)
        else:
            report_text = request.form.get("report", "").strip()
            if report_text:
                try:
                    report_data = json.loads(report_text)
                    results = triage_report(report_data)
                except json.JSONDecodeError as e:
                    error = f"That doesn't look like valid JSON: {e}"
                except Exception as e:
                    error = f"Could not triage that report: {e}"

    return render_template("index.html", report_text=report_text, results=results, error=error)


if __name__ == "__main__":
    # Port 5001 (not 5000): on macOS, AirPlay Receiver uses port 5000.
    # debug=True enables auto-reload -- when you edit and save a file,
    # the server restarts itself, so refreshing the page shows your changes.
    # Note: disable debug before any public deployment.
    print("Open http://127.0.0.1:5001 in your browser")
    app.run(port=5001, debug=True)