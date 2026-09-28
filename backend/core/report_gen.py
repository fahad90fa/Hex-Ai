# language: Python, file: backend/core/report_gen.py
# ReportGenerator with Jinja2 templates + WeasyPrint PDF
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, BaseLoader, select_autoescape

logger = logging.getLogger(__name__)
_report_generator: "ReportGenerator | None" = None

# ─── Inline Jinja2 Templates ─────────────────────────────────────────────────

EXECUTIVE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>{{ title }} — Executive Summary</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 900px; margin: 40px auto; color: #222; }
    h1 { color: #c0392b; } h2 { color: #2c3e50; border-bottom: 2px solid #ecf0f1; }
    .meta { background: #f8f9fa; padding: 12px; border-radius: 4px; margin-bottom: 20px; }
    .critical { color: #c0392b; font-weight: bold; }
    .high { color: #e67e22; font-weight: bold; }
    .medium { color: #f39c12; }
    .low { color: #27ae60; }
    .summary { line-height: 1.7; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background: #2c3e50; color: white; }
    tr:nth-child(even) { background: #f9f9f9; }
  </style>
</head>
<body>
  <h1>{{ title }}</h1>
  <div class="meta">
    <strong>Target:</strong> {{ target }}<br/>
    <strong>Generated:</strong> {{ generated_at }}<br/>
    <strong>Session:</strong> {{ session_id }}
  </div>
  <h2>Executive Summary</h2>
  <div class="summary">{{ executive_summary | replace('\\n', '<br/>') | safe }}</div>
  <h2>Findings Overview</h2>
  <table>
    <tr><th>Severity</th><th>Count</th></tr>
    <tr><td class="critical">CRITICAL</td><td>{{ critical_count }}</td></tr>
    <tr><td class="high">HIGH</td><td>{{ high_count }}</td></tr>
    <tr><td class="medium">MEDIUM</td><td>{{ medium_count }}</td></tr>
    <tr><td class="low">LOW</td><td>{{ low_count }}</td></tr>
    <tr><td>INFO</td><td>{{ info_count }}</td></tr>
    <tr><td><strong>Total</strong></td><td><strong>{{ total_count }}</strong></td></tr>
  </table>
  {% if top_findings %}
  <h2>Top Findings</h2>
  {% for f in top_findings %}
  <div style="margin:12px 0; padding:10px; border-left:4px solid #c0392b;">
    <strong>{{ f.title }}</strong> [{{ f.severity }}] — {{ f.affected_asset }}<br/>
    <small>{{ f.description[:300] }}</small>
  </div>
  {% endfor %}
  {% endif %}
</body>
</html>"""

TECHNICAL_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>{{ title }} — Technical Report</title>
  <style>
    body { font-family: 'Courier New', monospace; max-width: 1000px; margin: 40px auto; color: #1a1a2e; }
    h1 { color: #c0392b; } h2 { color: #16213e; } h3 { color: #0f3460; }
    .meta { background: #eee; padding: 10px; border-radius: 4px; margin-bottom: 20px; font-family: Arial; }
    .finding { background: #f9f9f9; border: 1px solid #ddd; padding: 16px; margin: 16px 0; border-radius: 4px; }
    .CRITICAL { border-left: 5px solid #c0392b; }
    .HIGH { border-left: 5px solid #e67e22; }
    .MEDIUM { border-left: 5px solid #f39c12; }
    .LOW { border-left: 5px solid #27ae60; }
    .evidence { background: #1a1a2e; color: #a8d8ea; padding: 10px; border-radius: 3px; overflow-x: auto; white-space: pre-wrap; font-size: 12px; }
    .chain { background: #fff3cd; padding: 10px; margin: 8px 0; border-radius: 4px; }
    code { background: #eee; padding: 2px 4px; border-radius: 2px; }
  </style>
</head>
<body>
  <h1>{{ title }}</h1>
  <div class="meta">
    <strong>Target:</strong> {{ target }} | <strong>Session:</strong> {{ session_id }} | <strong>Generated:</strong> {{ generated_at }}
  </div>
  <h2>Executive Summary</h2>
  <p>{{ executive_summary }}</p>
  <h2>Detailed Findings ({{ findings | length }})</h2>
  {% for f in findings %}
  <div class="finding {{ f.severity }}">
    <h3>{{ loop.index }}. {{ f.title }}</h3>
    <p><strong>Severity:</strong> {{ f.severity }} | <strong>CVSS:</strong> {{ f.cvss_score or 'N/A' }} | <strong>Asset:</strong> {{ f.affected_asset }}</p>
    {% if f.cve_ids %}<p><strong>CVEs:</strong> {{ f.cve_ids | join(', ') }}</p>{% endif %}
    <p>{{ f.description }}</p>
    {% if f.evidence %}
    <div class="evidence">{{ f.evidence }}</div>
    {% endif %}
    {% if f.remediation %}<p><strong>Remediation:</strong> {{ f.remediation }}</p>{% endif %}
  </div>
  {% endfor %}
  {% if exploit_chains %}
  <h2>Exploit Chains ({{ exploit_chains | length }})</h2>
  {% for chain in exploit_chains %}
  <div class="chain">
    <h3>{{ chain.chain_name or chain.cve_id }}</h3>
    <p><strong>Target CVE:</strong> {{ chain.cve_id }} | <strong>Confidence:</strong> {{ chain.confidence }}</p>
    <ol>{% for step in chain.get('steps', []) %}
      <li><strong>{{ step.description }}</strong> — Tool: <code>{{ step.tool }}</code></li>
    {% endfor %}</ol>
  </div>
  {% endfor %}
  {% endif %}
</body>
</html>"""

BUG_BOUNTY_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Bug Bounty Report — {{ title }}</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; color: #333; line-height: 1.6; }
    h1 { color: #2980b9; } h2 { color: #27ae60; border-bottom: 1px solid #eee; }
    .vuln { background: #fafafa; border: 1px solid #e0e0e0; padding: 20px; margin: 20px 0; border-radius: 6px; }
    .steps { background: #fff8e1; padding: 12px; border-radius: 4px; }
    code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
    pre { background: #272822; color: #f8f8f2; padding: 16px; border-radius: 4px; overflow-x: auto; }
  </style>
</head>
<body>
  <h1>Bug Bounty Report: {{ title }}</h1>
  <p><strong>Target:</strong> {{ target }} | <strong>Date:</strong> {{ generated_at }}</p>
  {% for f in findings if f.severity in ['CRITICAL', 'HIGH'] %}
  <div class="vuln">
    <h2>{{ f.title }}</h2>
    <p><strong>Severity:</strong> {{ f.severity }} | <strong>CVSS:</strong> {{ f.cvss_score or 'N/A' }}</p>
    <h3>Description</h3>
    <p>{{ f.description }}</p>
    <h3>Steps to Reproduce</h3>
    <div class="steps">
      <ol>
        <li>Target: <code>{{ f.affected_asset }}</code></li>
        <li>Evidence: <pre>{{ f.evidence[:1000] }}</pre></li>
      </ol>
    </div>
    <h3>Remediation</h3>
    <p>{{ f.remediation or 'No remediation provided.' }}</p>
  </div>
  {% endfor %}
</body>
</html>"""

TEMPLATES = {
    "executive": EXECUTIVE_TEMPLATE,
    "technical": TECHNICAL_TEMPLATE,
    "bug_bounty": BUG_BOUNTY_TEMPLATE,
}


class ReportGenerator:
    def __init__(self):
        self._env = Environment(loader=BaseLoader(), autoescape=select_autoescape(["html"]))

    async def generate(
        self,
        session_id: str,
        report_data: dict,
        template: str = "technical",
        title: str = "NEXUS Penetration Test Report",
    ) -> tuple[str, str]:
        """
        Generate HTML and PDF reports.
        Returns (html_path, pdf_path).
        """
        from ..config import get_settings
        settings = get_settings()
        report_dir = Path(settings.data_dir) / "sessions" / session_id / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)

        report_id = str(uuid.uuid4())[:8]
        html_path = str(report_dir / f"report_{report_id}.html")
        pdf_path = str(report_dir / f"report_{report_id}.pdf")

        findings = report_data.get("findings", [])
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "INFO").upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        template_str = TEMPLATES.get(template, TECHNICAL_TEMPLATE)
        tmpl = self._env.from_string(template_str)

        html_content = tmpl.render(
            title=title,
            target=report_data.get("target", ""),
            session_id=session_id,
            generated_at=report_data.get("generated_at", datetime.now(timezone.utc).isoformat()),
            executive_summary=report_data.get("executive_summary", ""),
            findings=findings,
            exploit_chains=report_data.get("exploit_chains", []),
            cve_matches=report_data.get("cve_matches", []),
            critical_count=severity_counts["CRITICAL"],
            high_count=severity_counts["HIGH"],
            medium_count=severity_counts["MEDIUM"],
            low_count=severity_counts["LOW"],
            info_count=severity_counts["INFO"],
            total_count=len(findings),
            top_findings=findings[:5],
        )

        # Write HTML
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        # Generate PDF with WeasyPrint
        try:
            from weasyprint import HTML
            HTML(string=html_content).write_pdf(pdf_path)
            logger.info(f"PDF report written: {pdf_path}")
        except Exception as e:
            logger.warning(f"WeasyPrint PDF generation failed: {e}")
            pdf_path = ""

        return html_path, pdf_path


def get_report_generator() -> ReportGenerator:
    global _report_generator
    if _report_generator is None:
        _report_generator = ReportGenerator()
    return _report_generator
