"""
web/app.py
----------
A small Flask dashboard for browsing triaged, prioritized findings in
the browser instead of the terminal. Read-only by design — it doesn't
trigger ingestion or AI triage itself (that still happens via the CLI),
it just gives you a visually clean way to review results.

Run with:
    cd web
    python app.py

Then open http://127.0.0.1:5050
"""

import os
import sys

# Allow importing models.py from the parent project directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask import Flask, render_template
import models

app = Flask(__name__)


def severity_info(cvss):
    """Maps a CVSS float to a (label, css_class) pair used throughout the UI."""
    if cvss is None:
        return "Unknown", "unknown"
    if cvss >= 9.0:
        return "Critical", "critical"
    if cvss >= 7.0:
        return "High", "high"
    if cvss >= 4.0:
        return "Medium", "medium"
    return "Low", "low"


@app.route("/")
def dashboard():
    all_findings = models.get_all_findings()
    scored = [f for f in all_findings if f["status"] == "scored"]
    scored.sort(key=lambda f: f.get("priority_rank") or 9999)

    for f in scored:
        f["severity_label"], f["severity_class"] = severity_info(f.get("ai_cvss_score"))

    stats = {
        "total": len(all_findings),
        "scored": len(scored),
        "pending": len(all_findings) - len(scored),
        "critical": sum(1 for f in scored if f["severity_class"] == "critical"),
        "high": sum(1 for f in scored if f["severity_class"] == "high"),
        "medium": sum(1 for f in scored if f["severity_class"] == "medium"),
        "low": sum(1 for f in scored if f["severity_class"] == "low"),
    }

    return render_template("dashboard.html", findings=scored, stats=stats)


if __name__ == "__main__":
    models.init_db()
    app.run(debug=True, host="127.0.0.1", port=5050)
