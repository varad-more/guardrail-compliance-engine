from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime
from html import escape

from ..core.models import Finding, ResourceEvaluation, ScanResult


def build_html_report(results: Iterable[ScanResult]) -> str:
    """Render a self-contained HTML compliance report."""
    results = list(results)

    passed = sum(1 for s in results for r in s.resources for f in r.findings if f.status == "PASS")
    failed = sum(1 for s in results for r in s.resources for f in r.findings if f.status == "FAIL")
    warned  = sum(1 for s in results for r in s.resources for f in r.findings if f.status == "WARN")
    total   = max(passed + failed + warned, 1)
    score   = round((passed / total) * 100)
    timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    # Severity breakdown across all FAIL findings
    sev_counts: Counter[str] = Counter(
        f.severity
        for s in results for r in s.resources for f in r.findings
        if f.status == "FAIL"
    )

    # Top 5 failing rules
    rule_fails: Counter[str] = Counter(
        f"{f.rule_id}: {f.title}"
        for s in results for r in s.resources for f in r.findings
        if f.status == "FAIL"
    )

    sections = "\n".join(_scan_section(scan) for scan in results)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>GuardRail Compliance Report</title>
  <style>
    :root {{
      --bg: #0f172a; --panel: #111827; --muted: #94a3b8; --text: #e5e7eb;
      --ok: #22c55e; --fail: #ef4444; --warn: #f59e0b; --accent: #38bdf8;
      --border: #334155; --high: #ef4444; --medium: #f59e0b; --low: #38bdf8;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: Inter, system-ui, sans-serif; background: var(--bg); color: var(--text); }}
    .wrap {{ max-width: 1100px; margin: 0 auto; padding: 32px 20px 64px; }}
    .hero, .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 16px; padding: 20px; margin-bottom: 20px; }}
    .hero h1 {{ margin-top: 0; }}
    .summary {{ display: flex; flex-wrap: wrap; gap: 24px; align-items: center; }}
    .stats {{ display: flex; gap: 16px; flex-wrap: wrap; }}
    .stat {{ min-width: 120px; padding: 12px 16px; border: 1px solid var(--border); border-radius: 12px; background: rgba(255,255,255,0.02); }}
    .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }}
    .value {{ font-size: 28px; font-weight: 700; margin-top: 4px; }}
    .badge {{ display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 700; }}
    .PASS {{ background: rgba(34,197,94,.18); color: #86efac; }}
    .FAIL {{ background: rgba(239,68,68,.18); color: #fca5a5; }}
    .WARN {{ background: rgba(245,158,11,.18); color: #fcd34d; }}
    .charts-row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }}
    @media (max-width: 700px) {{ .charts-row {{ grid-template-columns: 1fr; }} }}
    details {{ border: 1px solid var(--border); border-radius: 12px; padding: 12px 14px; margin-top: 12px; background: rgba(255,255,255,0.02); }}
    summary {{ cursor: pointer; font-weight: 700; }}
    pre {{ white-space: pre-wrap; word-break: break-word; background: #020617; border: 1px solid var(--border); border-radius: 12px; padding: 12px; color: #cbd5e1; }}
    .finding {{ margin: 12px 0; padding: 14px; border: 1px solid var(--border); border-radius: 12px; background: rgba(255,255,255,0.02); }}
    .finding h4 {{ margin: 8px 0; }}
    .muted {{ color: var(--muted); }}
    table {{ width: 100%; border-collapse: collapse; }}
    th {{ text-align: left; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; padding: 8px 12px; border-bottom: 1px solid var(--border); }}
    td {{ padding: 10px 12px; border-bottom: 1px solid rgba(51,65,85,0.5); font-size: 14px; }}
    tr:last-child td {{ border-bottom: none; }}
    .bar-track {{ background: rgba(255,255,255,0.07); border-radius: 6px; height: 12px; min-width: 160px; overflow: hidden; display: inline-block; }}
    .bar-fill {{ height: 12px; border-radius: 6px; }}
    .sev-row {{ display: flex; align-items: center; gap: 12px; margin: 10px 0; }}
    .sev-label {{ width: 70px; font-size: 13px; font-weight: 600; }}
    .sev-count {{ width: 36px; text-align: right; font-size: 13px; color: var(--muted); }}
    .rule-rank {{ color: var(--muted); font-size: 13px; min-width: 24px; }}
    .rule-id {{ font-family: monospace; font-size: 12px; color: var(--accent); }}
    @media print {{ body {{ background: white; color: black; }} }}
  </style>
</head>
<body>
  <div class="wrap">

    <!-- Hero -->
    <section class="hero">
      <h1>GuardRail Compliance Report</h1>
      <p class="muted">Generated {escape(timestamp)}</p>
      <div class="summary">
        {_donut(score)}
        <div class="stats">
          <div class="stat"><div class="label">Score</div><div class="value">{score}%</div></div>
          <div class="stat"><div class="label">Passed</div><div class="value" style="color:var(--ok)">{passed}</div></div>
          <div class="stat"><div class="label">Failed</div><div class="value" style="color:var(--fail)">{failed}</div></div>
          <div class="stat"><div class="label">Warnings</div><div class="value" style="color:var(--warn)">{warned}</div></div>
          <div class="stat"><div class="label">Files</div><div class="value">{len(results)}</div></div>
        </div>
      </div>
    </section>

    <!-- Charts row -->
    <div class="charts-row">
      {_severity_chart(sev_counts)}
      {_top_rules_chart(rule_fails)}
    </div>

    <!-- Per-file table -->
    {_files_table(results)}

    <!-- Findings detail -->
    {sections}

  </div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Visualization helpers
# ---------------------------------------------------------------------------

def _severity_chart(sev_counts: Counter[str]) -> str:
    """Horizontal bar chart for FAIL finding severity breakdown."""
    order = [("CRITICAL", "#dc2626"), ("HIGH", "#ef4444"), ("MEDIUM", "#f59e0b"), ("LOW", "#38bdf8"), ("INFORMATIONAL", "#a78bfa")]
    max_val = max(sev_counts.values(), default=1)
    rows = ""
    for sev, color in order:
        count = sev_counts.get(sev, 0)
        if count == 0 and not sev_counts:
            continue
        width_pct = round((count / max_val) * 100) if max_val else 0
        rows += f"""
        <div class="sev-row">
          <span class="sev-label" style="color:{color}">{escape(sev[:6])}</span>
          <div class="bar-track" style="flex:1">
            <div class="bar-fill" style="width:{width_pct}%;background:{color}"></div>
          </div>
          <span class="sev-count">{count}</span>
        </div>"""

    empty_msg = '<p class="muted" style="margin:0">No failures detected.</p>' if not sev_counts else ""
    return f"""
    <div class="card">
      <div class="label" style="margin-bottom:16px">Failures by severity</div>
      {rows}
      {empty_msg}
    </div>"""


def _top_rules_chart(rule_fails: Counter[str]) -> str:
    """Leaderboard of the top 5 most-failing rules."""
    top = rule_fails.most_common(5)
    if not top:
        return """
    <div class="card">
      <div class="label" style="margin-bottom:16px">Top failing rules</div>
      <p class="muted" style="margin:0">No failures detected.</p>
    </div>"""

    max_val = top[0][1]
    rows = ""
    for i, (label, count) in enumerate(top, 1):
        rule_id, _, title = label.partition(": ")
        width_pct = round((count / max_val) * 100)
        rows += f"""
        <div style="margin:10px 0">
          <div style="display:flex;justify-content:space-between;margin-bottom:4px">
            <span><span class="rule-rank">#{i}</span> <span class="rule-id">{escape(rule_id)}</span>
              <span style="font-size:13px;color:var(--muted);margin-left:6px">{escape(title[:48])}</span></span>
            <span style="font-size:13px;color:var(--fail);font-weight:700">{count}</span>
          </div>
          <div class="bar-track" style="width:100%">
            <div class="bar-fill" style="width:{width_pct}%;background:var(--fail)"></div>
          </div>
        </div>"""

    return f"""
    <div class="card">
      <div class="label" style="margin-bottom:16px">Top failing rules</div>
      {rows}
    </div>"""


def _files_table(results: list[ScanResult]) -> str:
    """Per-file summary table showing resource count, pass/fail/warn totals."""
    if not results:
        return ""

    rows = ""
    for scan in results:
        file_pass = sum(1 for r in scan.resources for f in r.findings if f.status == "PASS")
        file_fail = sum(1 for r in scan.resources for f in r.findings if f.status == "FAIL")
        file_warn = sum(1 for r in scan.resources for f in r.findings if f.status == "WARN")
        file_total = max(file_pass + file_fail + file_warn, 1)
        file_score = round((file_pass / file_total) * 100)
        score_color = "var(--ok)" if file_score >= 80 else ("var(--warn)" if file_score >= 50 else "var(--fail)")
        status_icon = "✓" if file_fail == 0 else "✗"
        icon_color = "var(--ok)" if file_fail == 0 else "var(--fail)"
        rows += f"""
        <tr>
          <td style="color:{icon_color};font-weight:700">{status_icon}</td>
          <td style="font-family:monospace;font-size:13px">{escape(str(scan.file_path))}</td>
          <td>{len(scan.resources)}</td>
          <td style="color:var(--ok)">{file_pass}</td>
          <td style="color:var(--fail)">{file_fail}</td>
          <td style="color:var(--warn)">{file_warn}</td>
          <td style="font-weight:700;color:{score_color}">{file_score}%</td>
        </tr>"""

    return f"""
    <section class="card">
      <div class="label" style="margin-bottom:16px">Files scanned</div>
      <table>
        <thead>
          <tr>
            <th></th><th>File</th><th>Resources</th>
            <th>Pass</th><th>Fail</th><th>Warn</th><th>Score</th>
          </tr>
        </thead>
        <tbody>{rows}</tbody>
      </table>
    </section>"""


# ---------------------------------------------------------------------------
# Finding detail sections (unchanged structure, minor style tweaks)
# ---------------------------------------------------------------------------

def _scan_section(scan: ScanResult) -> str:
    resources = "\n".join(_resource_section(resource) for resource in scan.resources)
    fail_count = scan.failed_findings
    status_badge = f'<span class="badge FAIL">{fail_count} failure{"s" if fail_count != 1 else ""}</span>' if fail_count else '<span class="badge PASS">Clean</span>'
    return f"""
    <section class="card">
      <h2 style="margin-top:0">{escape(str(scan.file_path))} {status_badge}</h2>
      <p class="muted">Parser: {escape(scan.parser)}</p>
      {resources}
    </section>"""


def _resource_section(resource: ResourceEvaluation) -> str:
    findings = "\n".join(_finding_block(finding) for finding in resource.findings)
    has_fail = any(f.status == "FAIL" for f in resource.findings)
    icon = "🔴" if has_fail else "🟢"
    return f"""
    <details>
      <summary>{icon} {escape(resource.resource_type)}.{escape(resource.resource_name)}</summary>
      <p class="muted">Line: {resource.line_number or 'n/a'}</p>
      <pre>{escape(resource.normalized_text)}</pre>
      {findings}
    </details>"""


def _finding_block(finding: Finding) -> str:
    remediation = f"<p><strong>Remediation:</strong> {escape(finding.remediation)}</p>" if finding.remediation else ""
    proof = f"<pre>{escape(finding.proof)}</pre>" if finding.proof else ""
    return f"""
    <div class="finding">
      <span class="badge {escape(finding.status)}">{escape(finding.status)}</span>
      <span class="badge">{escape(finding.severity)}</span>
      <h4 style="margin:8px 0">{escape(finding.rule_id)} — {escape(finding.title)}</h4>
      <p>{escape(finding.message)}</p>
      {remediation}
      {proof}
    </div>"""


def _donut(score: int) -> str:
    circumference = 2 * 3.14159 * 54
    filled = circumference * (score / 100)
    color = "#22c55e" if score >= 80 else ("#f59e0b" if score >= 50 else "#ef4444")
    return f"""
    <svg width="160" height="160" viewBox="0 0 160 160" role="img" aria-label="Compliance score {score}%">
      <circle cx="80" cy="80" r="54" fill="none" stroke="#1e293b" stroke-width="16" />
      <circle cx="80" cy="80" r="54" fill="none" stroke="{color}" stroke-width="16"
              stroke-dasharray="{filled:.2f} {circumference:.2f}" transform="rotate(-90 80 80)" stroke-linecap="round" />
      <text x="80" y="86" text-anchor="middle" font-size="28" fill="#e5e7eb" font-weight="700">{score}%</text>
    </svg>"""
