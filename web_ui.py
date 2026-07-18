"""
A very small local web UI for bandit-triage.

Run it with:
    python3 web_ui.py
then open http://127.0.0.1:5000 in your browser.

Paste a Bandit JSON report (from `bandit -r . -f json`) into the box, or
click "Load example" to use the bundled sample, and it renders the triaged,
explained results visually instead of as terminal text.
"""
import json

from flask import Flask, render_template_string, request

from bandit_triage.classifier import TriageClassifier
from bandit_triage.features import extract_features
from bandit_triage.loader import Finding, _extract_cwe
from bandit_triage.cli import describe_contribution

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
            )
        )

    scored = []
    for f in findings:
        pred = model.predict(extract_features(f))
        top = pred.contributions[0] if pred.label == "likely_true_positive" else pred.contributions[-1]
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


PAGE = """
<!DOCTYPE html>
<html>
<head>
  <title>bandit-triage</title>
  <style>
    :root { --tp: #c0392b; --fp: #7f8c8d; --bg: #f5f5f3; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 0; background: var(--bg); color: #1a1a1a; }
    header { background: #1e2327; color: white; padding: 18px 32px; }
    header h1 { margin: 0; font-size: 18px; font-weight: 600; }
    header p { margin: 4px 0 0; font-size: 13px; color: #b0b8c0; }
    main { max-width: 880px; margin: 0 auto; padding: 24px 32px; }
    textarea { width: 100%; height: 160px; font-family: ui-monospace, monospace; font-size: 12px; padding: 10px; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; resize: vertical; }
    .btnrow { margin: 12px 0 24px; display: flex; gap: 10px; }
    button { font-size: 14px; padding: 8px 18px; border-radius: 6px; border: 1px solid #1e2327; background: #1e2327; color: white; cursor: pointer; }
    button.secondary { background: white; color: #1e2327; }
    .summary { font-size: 14px; color: #444; margin-bottom: 16px; }
    .card { background: white; border-radius: 8px; border: 1px solid #e4e4e0; padding: 14px 16px; margin-bottom: 12px; border-left: 4px solid var(--fp); }
    .card.tp { border-left-color: var(--tp); }
    .cardhead { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; }
    .loc { font-family: ui-monospace, monospace; font-size: 13px; font-weight: 600; }
    .badge { font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 10px; white-space: nowrap; }
    .badge.tp { background: #fdecea; color: var(--tp); }
    .badge.fp { background: #eef0f0; color: var(--fp); }
    .rule { font-size: 12px; color: #888; font-family: ui-monospace, monospace; }
    .issue { font-size: 13px; margin: 6px 0; }
    .reason { font-size: 13px; color: #333; background: #f8f8f6; padding: 6px 10px; border-radius: 4px; margin-top: 6px; }
    .cwe { font-size: 12px; }
    .cwe a { color: #2c6cb0; }
    pre.code { font-size: 12px; background: #1e2327; color: #e0e0e0; padding: 8px 10px; border-radius: 4px; overflow-x: auto; margin: 8px 0 0; }
    .error { color: var(--tp); font-size: 14px; }
  </style>
</head>
<body>
  <header>
    <h1>bandit-triage</h1>
    <p>Re-prioritizes Bandit findings by predicted true-positive likelihood, with explanations.</p>
  </header>
  <main>
    <form method="post">
      <textarea name="report" placeholder="Paste a Bandit JSON report here (bandit -r . -f json)...">{{ report_text }}</textarea>
      <div class="btnrow">
        <button type="submit">Triage findings</button>
        <button type="submit" name="load_example" value="1" class="secondary">Load example report</button>
      </div>
    </form>

    {% if error %}<p class="error">{{ error }}</p>{% endif %}

    {% if results is not none %}
      <p class="summary">{{ results|length }} findings ·
        {{ results|selectattr('label', 'equalto', 'likely_true_positive')|list|length }} likely true positive,
        {{ results|selectattr('label', 'equalto', 'likely_false_positive')|list|length }} likely false positive
        (sorted, most likely real first)</p>

      {% for r in results %}
        <div class="card {{ 'tp' if r.label == 'likely_true_positive' else 'fp' }}">
          <div class="cardhead">
            <span class="loc">{{ r.filename }}:{{ r.line_number }}</span>
            <span class="badge {{ 'tp' if r.label == 'likely_true_positive' else 'fp' }}">
              {{ 'LIKELY REAL' if r.label == 'likely_true_positive' else 'LIKELY NOISE' }} · p={{ '%.2f'|format(r.prob) }}
            </span>
          </div>
          <div class="rule">{{ r.test_id }} {{ r.test_name }} · Bandit severity: {{ r.bandit_severity }}</div>
          <div class="issue">{{ r.issue_text }}</div>
          {% if r.cwe_id %}<div class="cwe">Reference: <a href="{{ r.cwe_link }}" target="_blank">CWE-{{ r.cwe_id }}</a></div>{% endif %}
          <div class="reason"><strong>Why:</strong> {{ r.reason }}</div>
          {% if r.code %}<pre class="code">{{ r.code.rstrip() }}</pre>{% endif %}
        </div>
      {% endfor %}
    {% endif %}
  </main>
</body>
</html>
"""


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

    return render_template_string(PAGE, report_text=report_text, results=results, error=error)


if __name__ == "__main__":
    print("Open http://127.0.0.1:5000 in your browser")
    app.run(port=5000, debug=False)
