"""
dashboard.py
Flask web dashboard to view AI incident reports in the browser.
Run: python src/dashboard.py
Open: http://localhost:5000
"""

import sys
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template_string, abort
import markdown2

sys.path.insert(0, str(Path(__file__).parent))

REPORTS_DIR = Path("data/reports")

app = Flask(__name__)

BASE_HTML = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           background: #f5f5f5; color: #333; }
    .nav { background: #1a3a6b; color: white; padding: 1rem 2rem;
           display: flex; align-items: center; gap: 1rem; }
    .nav h1 { font-size: 1.2rem; font-weight: 600; }
    .nav a { color: #9FC5F8; text-decoration: none; font-size: 0.9rem; }
    .container { max-width: 960px; margin: 2rem auto; padding: 0 1rem; }
    .card { background: white; border-radius: 8px; border: 1px solid #e0e0e0;
            padding: 1.5rem; margin-bottom: 1rem; }
    .badge { display: inline-block; padding: 3px 10px; border-radius: 12px;
             font-size: 0.75rem; font-weight: 600; margin-right: 8px; }
    .badge-critical { background: #fee2e2; color: #991b1b; }
    .badge-high     { background: #ffedd5; color: #9a3412; }
    .badge-medium   { background: #fef9c3; color: #854d0e; }
    .badge-low      { background: #dcfce7; color: #166534; }
    .badge-unknown  { background: #f3f4f6; color: #374151; }
    .report-title { font-size: 1rem; font-weight: 600; margin-bottom: 0.5rem; }
    .report-meta  { font-size: 0.85rem; color: #666; }
    .report-link  { display: inline-block; margin-top: 0.75rem; color: #1a3a6b;
                    text-decoration: none; font-size: 0.9rem; font-weight: 500; }
    .report-link:hover { text-decoration: underline; }
    .empty { text-align: center; color: #888; padding: 3rem; }
    .report-body { line-height: 1.7; }
    .report-body h1 { font-size: 1.4rem; margin: 1rem 0 0.5rem; color: #1a3a6b; }
    .report-body h2 { font-size: 1.1rem; margin: 1.2rem 0 0.4rem; color: #2e5ba8; }
    .report-body p  { margin-bottom: 0.75rem; }
    .report-body ol,.report-body ul { margin: 0.5rem 0 0.75rem 1.5rem; }
    .report-body li { margin-bottom: 0.3rem; }
    .report-body code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px;
                        font-family: monospace; font-size: 0.9em; }
    .back-btn { display: inline-block; margin-bottom: 1rem; color: #1a3a6b;
                text-decoration: none; font-size: 0.9rem; }
    .back-btn:hover { text-decoration: underline; }
    .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin-bottom: 1.5rem; }
    .stat-card { background: white; border-radius: 8px; border: 1px solid #e0e0e0;
                 padding: 1rem; text-align: center; }
    .stat-num { font-size: 2rem; font-weight: 700; color: #1a3a6b; }
    .stat-label { font-size: 0.8rem; color: #888; margin-top: 0.25rem; }
  </style>
</head>
<body>
  <nav class="nav">
    <h1>AI Log Analyser</h1>
    <a href="/">All Reports</a>
  </nav>
  <div class="container">
    {% block content %}{% endblock %}
  </div>
</body>
</html>
"""

INDEX_HTML = BASE_HTML.replace(
    "{% block content %}{% endblock %}",
    """
    <div class="stats">
      <div class="stat-card">
        <div class="stat-num">{{ total }}</div>
        <div class="stat-label">Total reports</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">{{ ai_count }}</div>
        <div class="stat-label">AI reports</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">{{ critical_count }}</div>
        <div class="stat-label">Critical incidents</div>
      </div>
    </div>

    {% if reports %}
      {% for r in reports %}
      <div class="card">
        <div>
          <span class="badge badge-{{ r.severity_class }}">{{ r.severity }}</span>
          {% if r.is_ai %}<span class="badge" style="background:#ede9fe;color:#4c1d95">AI</span>{% endif %}
        </div>
        <div class="report-title" style="margin-top:0.5rem">{{ r.filename }}</div>
        <div class="report-meta">{{ r.date_display }} &nbsp;|&nbsp; {{ r.size }} lines</div>
        <a class="report-link" href="/report/{{ r.filename }}">View full report →</a>
      </div>
      {% endfor %}
    {% else %}
      <div class="empty">
        <p>No reports yet.</p>
        <p style="margin-top:0.5rem;font-size:0.9rem">
          Run: python src/log_monitor.py --log data/sample.log --ai --telegram
        </p>
      </div>
    {% endif %}
    """
)

REPORT_HTML = BASE_HTML.replace(
    "{% block content %}{% endblock %}",
    """
    <a class="back-btn" href="/">← Back to all reports</a>
    <div class="card">
      <div class="report-body">{{ content | safe }}</div>
    </div>
    """
)


def get_severity(content: str) -> str:
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if level in content:
            return level
    return "UNKNOWN"


def severity_class(severity: str) -> str:
    return severity.lower() if severity in ["CRITICAL","HIGH","MEDIUM","LOW"] else "unknown"


def get_reports() -> list:
    if not REPORTS_DIR.exists():
        return []
    reports = []
    for f in sorted(REPORTS_DIR.glob("*.md"), reverse=True):
        content = f.read_text()
        severity = get_severity(content)
        reports.append({
            "filename":       f.name,
            "severity":       severity,
            "severity_class": severity_class(severity),
            "is_ai":          "_ai" in f.name,
            "size":           len(content.splitlines()),
            "date_display":   f.stem.replace("incident_","").replace("T"," ").replace("_ai",""),
        })
    return reports


@app.route("/")
def index():
    reports = get_reports()
    ai_count = sum(1 for r in reports if r["is_ai"])
    critical_count = sum(1 for r in reports if r["severity"] == "CRITICAL")
    return render_template_string(
        INDEX_HTML,
        reports=reports,
        total=len(reports),
        ai_count=ai_count,
        critical_count=critical_count,
        title="AI Log Analyser — Reports",
    )


@app.route("/report/<filename>")
def report(filename: str):
    path = REPORTS_DIR / filename
    if not path.exists():
        abort(404)
    content = markdown2.markdown(
        path.read_text(),
        extras=["fenced-code-blocks", "tables"]
    )
    return render_template_string(
        REPORT_HTML,
        content=content,
        title=filename,
    )


if __name__ == "__main__":
    print("Dashboard running at http://localhost:5000")
    print("Press Ctrl+C to stop.\n")
    app.run(debug=True, port=5000)
