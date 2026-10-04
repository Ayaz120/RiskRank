"""
reports/report_generator.py
-----------------------------
Turns the scored findings in the database into a clean, professional
HTML report — the actual deliverable you'd show a client, hand to a
recruiter, or drop into your GitHub as a sample output.

Design notes:
- All finding text (titles, descriptions, AI output) is HTML-escaped
  before being inserted into the page. This matters more than it might
  seem: this data could eventually come from untrusted input (e.g. a
  malicious server banner, or someone else's submitted Nmap scan), so
  without escaping, a finding's own text could inject a working XSS
  payload into the report that views it. Handling this correctly is
  itself a good example of security-aware coding to point to in an
  interview — a "security tool" that reflects unescaped input into
  HTML would be a little embarrassing to explain otherwise.
"""

import os
import html
from datetime import datetime

import models

REPORT_PATH = os.path.join(os.path.dirname(__file__), "triage_report.html")


def _esc(value) -> str:
    """Shorthand for HTML-escaping any value before it goes into the page."""
    return html.escape(str(value)) if value is not None else ""


def _severity_class(cvss: float) -> str:
    if cvss is None:
        return "sev-unknown"
    if cvss >= 9.0:
        return "sev-critical"
    if cvss >= 7.0:
        return "sev-high"
    if cvss >= 4.0:
        return "sev-medium"
    return "sev-low"


def _severity_label(cvss: float) -> str:
    if cvss is None:
        return "Unknown"
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    return "Low"


def _render_finding_row(f: dict) -> str:
    cvss = f.get("ai_cvss_score")
    sev_class = _severity_class(cvss)
    sev_label = _severity_label(cvss)

    return f"""
    <div class="finding {sev_class}">
        <div class="finding-header">
            <span class="rank-badge">#{_esc(f.get('priority_rank', '-'))}</span>
            <h3>{_esc(f['title'])}</h3>
            <span class="severity-badge {sev_class}">{sev_label} ({_esc(cvss)})</span>
        </div>
        <div class="finding-meta">
            <span><strong>Asset:</strong> {_esc(f['asset'])}</span>
            <span><strong>Source:</strong> {_esc(f['source'])}</span>
            <span><strong>Exploitability:</strong> {_esc(f.get('ai_exploitability', 'n/a'))}</span>
            <span><strong>Asset criticality:</strong> {_esc(f.get('asset_criticality', 'unknown'))}</span>
            <span><strong>Priority score:</strong> {_esc(f.get('priority_score', 'n/a'))} / 100</span>
        </div>
        <div class="finding-section">
            <h4>Description</h4>
            <p>{_esc(f.get('description', ''))}</p>
        </div>
        <div class="finding-section">
            <h4>Impact</h4>
            <p>{_esc(f.get('ai_explanation', ''))}</p>
        </div>
        <div class="finding-section">
            <h4>CVSS Reasoning</h4>
            <p>{_esc(f.get('ai_cvss_reasoning', ''))}</p>
        </div>
        <div class="finding-section">
            <h4>Remediation</h4>
            <p>{_esc(f.get('ai_remediation', ''))}</p>
        </div>
    </div>
    """


def generate_html_report() -> str:
    """
    Builds the full HTML report from every 'scored' finding in the
    database, writes it to REPORT_PATH, and returns the path.
    """
    findings = models.get_all_findings(status="scored")
    findings.sort(key=lambda f: f.get("priority_rank") or 9999)

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")

    total = len(findings)
    critical_count = sum(1 for f in findings if (f.get("ai_cvss_score") or 0) >= 9.0)
    high_count = sum(1 for f in findings if 7.0 <= (f.get("ai_cvss_score") or 0) < 9.0)
    medium_count = sum(1 for f in findings if 4.0 <= (f.get("ai_cvss_score") or 0) < 7.0)
    low_count = sum(1 for f in findings if (f.get("ai_cvss_score") or 0) < 4.0)

    findings_html = "\n".join(_render_finding_row(f) for f in findings) if findings else \
        "<p class='empty-state'>No prioritized findings yet. Run 'triage' then 'prioritize' first.</p>"

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Vulnerability Triage Report</title>
<style>
    :root {{
        --critical: #8b1e1e;
        --high: #c0392b;
        --medium: #d68910;
        --low: #2e7d32;
        --bg: #f4f5f7;
        --card-bg: #ffffff;
        --text: #1c1c1e;
        --muted: #6b7280;
        --border: #e5e7eb;
    }}
    * {{ box-sizing: border-box; }}
    body {{
        font-family: -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
        background: var(--bg);
        color: var(--text);
        margin: 0;
        padding: 0;
    }}
    .container {{
        max-width: 900px;
        margin: 0 auto;
        padding: 32px 20px 80px;
    }}
    header {{
        margin-bottom: 32px;
    }}
    header h1 {{
        margin: 0 0 4px;
        font-size: 1.6rem;
    }}
    header .subtitle {{
        color: var(--muted);
        font-size: 0.9rem;
    }}
    .summary {{
        display: flex;
        gap: 12px;
        margin: 24px 0 32px;
        flex-wrap: wrap;
    }}
    .summary-card {{
        background: var(--card-bg);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 14px 18px;
        flex: 1;
        min-width: 100px;
        text-align: center;
    }}
    .summary-card .count {{
        font-size: 1.6rem;
        font-weight: 700;
    }}
    .summary-card .label {{
        font-size: 0.78rem;
        color: var(--muted);
        text-transform: uppercase;
        letter-spacing: 0.03em;
    }}
    .summary-card.total .count {{ color: var(--text); }}
    .summary-card.critical .count {{ color: var(--critical); }}
    .summary-card.high .count {{ color: var(--high); }}
    .summary-card.medium .count {{ color: var(--medium); }}
    .summary-card.low .count {{ color: var(--low); }}

    .finding {{
        background: var(--card-bg);
        border: 1px solid var(--border);
        border-left: 5px solid var(--muted);
        border-radius: 10px;
        padding: 20px 22px;
        margin-bottom: 18px;
    }}
    .finding.sev-critical {{ border-left-color: var(--critical); }}
    .finding.sev-high {{ border-left-color: var(--high); }}
    .finding.sev-medium {{ border-left-color: var(--medium); }}
    .finding.sev-low {{ border-left-color: var(--low); }}

    .finding-header {{
        display: flex;
        align-items: center;
        gap: 10px;
        flex-wrap: wrap;
        margin-bottom: 8px;
    }}
    .finding-header h3 {{
        margin: 0;
        font-size: 1.05rem;
        flex: 1;
        min-width: 180px;
    }}
    .rank-badge {{
        background: var(--text);
        color: white;
        border-radius: 6px;
        padding: 2px 8px;
        font-size: 0.78rem;
        font-weight: 600;
    }}
    .severity-badge {{
        border-radius: 6px;
        padding: 2px 10px;
        font-size: 0.78rem;
        font-weight: 700;
        color: white;
    }}
    .severity-badge.sev-critical {{ background: var(--critical); }}
    .severity-badge.sev-high {{ background: var(--high); }}
    .severity-badge.sev-medium {{ background: var(--medium); }}
    .severity-badge.sev-low {{ background: var(--low); }}
    .severity-badge.sev-unknown {{ background: var(--muted); }}

    .finding-meta {{
        display: flex;
        gap: 16px;
        flex-wrap: wrap;
        font-size: 0.82rem;
        color: var(--muted);
        margin-bottom: 14px;
        padding-bottom: 12px;
        border-bottom: 1px solid var(--border);
    }}
    .finding-meta span {{
        margin-right: 16px;
        display: inline-block;
    }}
    .finding-section {{ margin-top: 10px; }}
    .finding-section h4 {{
        margin: 0 0 4px;
        font-size: 0.78rem;
        text-transform: uppercase;
        letter-spacing: 0.03em;
        color: var(--muted);
    }}
    .finding-section p {{
        margin: 0;
        font-size: 0.93rem;
        line-height: 1.5;
    }}
    .empty-state {{
        text-align: center;
        color: var(--muted);
        padding: 60px 0;
    }}
    footer {{
        text-align: center;
        color: var(--muted);
        font-size: 0.78rem;
        margin-top: 40px;
    }}
</style>
</head>
<body>
<div class="container">
    <header>
        <h1>Vulnerability Triage Report</h1>
        <div class="subtitle">Generated {_esc(generated_at)} &middot; AI-assisted triage &amp; risk-based prioritization</div>
    </header>

    <div class="summary">
        <div class="summary-card total">
            <div class="count">{total}</div>
            <div class="label">Total Findings</div>
        </div>
        <div class="summary-card critical">
            <div class="count">{critical_count}</div>
            <div class="label">Critical</div>
        </div>
        <div class="summary-card high">
            <div class="count">{high_count}</div>
            <div class="label">High</div>
        </div>
        <div class="summary-card medium">
            <div class="count">{medium_count}</div>
            <div class="label">Medium</div>
        </div>
        <div class="summary-card low">
            <div class="count">{low_count}</div>
            <div class="label">Low</div>
        </div>
    </div>

    {findings_html}

    <footer>
        Generated by AI-Powered Vulnerability Triage Assistant &middot; findings triaged locally via Ollama
    </footer>
</div>
</body>
</html>"""

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(page)

    return REPORT_PATH


if __name__ == "__main__":
    path = generate_html_report()
    print(f"Report written to: {path}")
