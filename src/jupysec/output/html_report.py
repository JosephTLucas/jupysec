"""HTML report generation using Jinja2."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, BaseLoader

from jupysec.core.finding import ScanResult

_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>jupysec Security Report</title>
<style>
  :root {
    --bg: #0d1117; --fg: #c9d1d9; --card: #161b22; --border: #30363d;
    --critical: #f85149; --high: #f0883e; --medium: #d29922;
    --low: #58a6ff; --info: #8b949e; --pass: #3fb950;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
         background: var(--bg); color: var(--fg); line-height: 1.6; padding: 2rem; }
  h1 { font-size: 1.8rem; margin-bottom: 0.5rem; }
  .meta { color: var(--info); margin-bottom: 2rem; font-size: 0.9rem; }
  .summary { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
  .stat { background: var(--card); border: 1px solid var(--border);
          border-radius: 8px; padding: 1rem 1.5rem; min-width: 120px; text-align: center; }
  .stat .num { font-size: 2rem; font-weight: 700; }
  .stat.critical .num { color: var(--critical); }
  .stat.high .num { color: var(--high); }
  .stat.medium .num { color: var(--medium); }
  .stat.low .num { color: var(--low); }
  .stat.info .num { color: var(--info); }
  .stat.pass .num { color: var(--pass); }
  .finding { background: var(--card); border: 1px solid var(--border);
             border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem;
             border-left: 4px solid var(--info); }
  .finding.critical { border-left-color: var(--critical); }
  .finding.high { border-left-color: var(--high); }
  .finding.medium { border-left-color: var(--medium); }
  .finding.low { border-left-color: var(--low); }
  .finding h3 { font-size: 1rem; margin-bottom: 0.4rem; }
  .badge { display: inline-block; font-size: 0.75rem; padding: 2px 8px;
           border-radius: 12px; font-weight: 600; text-transform: uppercase; margin-right: 0.5rem; }
  .badge.critical { background: var(--critical); color: #fff; }
  .badge.high { background: var(--high); color: #fff; }
  .badge.medium { background: var(--medium); color: #000; }
  .badge.low { background: var(--low); color: #000; }
  .badge.info { background: var(--info); color: #000; }
  .detail { margin-top: 0.5rem; font-size: 0.9rem; }
  .detail dt { font-weight: 600; margin-top: 0.5rem; }
  .detail dd { margin-left: 1rem; color: var(--info); }
  .pass-msg { background: var(--card); border: 1px solid var(--border);
              border-radius: 8px; padding: 2rem; text-align: center;
              color: var(--pass); font-size: 1.2rem; }
</style>
</head>
<body>
<h1>jupysec Security Report</h1>
<div class="meta">
  {% if target_url %}Target: {{ target_url }}<br>{% endif %}
  Mode: {{ mode }} &middot; Checks run: {{ checks_run }} &middot;
  {{ completed_at }}
</div>

<div class="summary">
  <div class="stat pass"><div class="num">{{ checks_passed }}</div>Passed</div>
  <div class="stat critical"><div class="num">{{ counts.get('critical', 0) }}</div>Critical</div>
  <div class="stat high"><div class="num">{{ counts.get('high', 0) }}</div>High</div>
  <div class="stat medium"><div class="num">{{ counts.get('medium', 0) }}</div>Medium</div>
  <div class="stat low"><div class="num">{{ counts.get('low', 0) }}</div>Low</div>
  <div class="stat info"><div class="num">{{ counts.get('info', 0) }}</div>Info</div>
</div>

{% if not findings %}
<div class="pass-msg">All checks passed. No findings to report.</div>
{% endif %}

{% for f in findings %}
<div class="finding {{ f.severity.value }}">
  <h3><span class="badge {{ f.severity.value }}">{{ f.severity.value }}</span>{{ f.title }}</h3>
  <p>{{ f.description }}</p>
  <dl class="detail">
    {% if f.evidence %}<dt>Evidence</dt><dd>{{ f.evidence }}</dd>{% endif %}
    {% if f.remediation %}<dt>Remediation</dt><dd>{{ f.remediation }}</dd>{% endif %}
    {% if f.cwe %}<dt>CWE</dt><dd>{{ f.cwe }}</dd>{% endif %}
    {% if f.target_component %}<dt>Component</dt><dd>{{ f.target_component }}</dd>{% endif %}
    {% if f.references %}<dt>References</dt><dd>{{ f.references | join(', ') }}</dd>{% endif %}
  </dl>
</div>
{% endfor %}
</body>
</html>
"""


def to_html(result: ScanResult) -> str:
    env = Environment(loader=BaseLoader(), autoescape=True)
    template = env.from_string(_TEMPLATE)
    return template.render(
        target_url=result.target_url,
        mode=result.mode,
        checks_run=result.checks_run,
        checks_passed=result.checks_passed,
        completed_at=result.completed_at.isoformat() if result.completed_at else "",
        counts=result.summary,
        findings=result.findings,
    )


def write_html(result: ScanResult, path: Path) -> None:
    path.write_text(to_html(result), encoding="utf-8")
