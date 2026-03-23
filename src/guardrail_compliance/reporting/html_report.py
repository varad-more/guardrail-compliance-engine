from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from typing import Iterable

from ..core.models import Finding, ResourceEvaluation, ScanResult


def build_html_report(results: Iterable[ScanResult]) -> str:
    results = list(results)
    passed = sum(1 for scan in results for resource in scan.resources for finding in resource.findings if finding.status == "PASS")
    failed = sum(1 for scan in results for resource in scan.resources for finding in resource.findings if finding.status == "FAIL")
    warned = sum(1 for scan in results for resource in scan.resources for finding in resource.findings if finding.status == "WARN")
    total = max(passed + failed + warned, 1)
    score = round((passed / total) * 100)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    sections = "\n".join(_scan_section(scan) for scan in results)
    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>GuardRail Compliance Report</title>
  <style>
    :root {{
      --bg: #0f172a;
      --panel: #111827;
      --muted: #94a3b8;
      --text: #e5e7eb;
      --ok: #22c55e;
      --fail: #ef4444;
      --warn: #f59e0b;
      --accent: #38bdf8;
      --border: #334155;
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
    details {{ border: 1px solid var(--border); border-radius: 12px; padding: 12px 14px; margin-top: 12px; background: rgba(255,255,255,0.02); }}
    summary {{ cursor: pointer; font-weight: 700; }}
    pre {{ white-space: pre-wrap; word-break: break-word; background: #020617; border: 1px solid var(--border); border-radius: 12px; padding: 12px; color: #cbd5e1; }}
    .finding {{ margin: 12px 0; padding: 14px; border: 1px solid var(--border); border-radius: 12px; background: rgba(255,255,255,0.02); }}
    .finding h4 {{ margin: 8px 0; }}
    .muted {{ color: var(--muted); }}
    @media print {{ body {{ background: white; color: black; }} .hero, .card, details, .finding {{ border-color: #ccc; background: white; }} pre {{ background: #fafafa; }} }}
  </style>
</head>
<body>
  <div class=\"wrap\">
    <section class=\"hero\">
      <h1>GuardRail Compliance Report</h1>
      <p class=\"muted\">Generated {escape(timestamp)} • Terraform-first MVP with Bedrock Guardrails integration hooks</p>
      <div class=\"summary\">
        {_donut(score)}
        <div class=\"stats\">
          <div class=\"stat\"><div class=\"label\">Compliance score</div><div class=\"value\">{score}%</div></div>
          <div class=\"stat\"><div class=\"label\">Passed</div><div class=\"value\">{passed}</div></div>
          <div class=\"stat\"><div class=\"label\">Failed</div><div class=\"value\">{failed}</div></div>
          <div class=\"stat\"><div class=\"label\">Warnings</div><div class=\"value\">{warned}</div></div>
          <div class=\"stat\"><div class=\"label\">Files</div><div class=\"value\">{len(results)}</div></div>
        </div>
      </div>
    </section>
    {sections}
  </div>
</body>
</html>"""


def _scan_section(scan: ScanResult) -> str:
    resources = "\n".join(_resource_section(resource) for resource in scan.resources)
    return f"""
    <section class=\"card\">
      <h2>{escape(str(scan.file_path))}</h2>
      <p class=\"muted\">Parser: {escape(scan.parser)}</p>
      {resources}
    </section>
    """


def _resource_section(resource: ResourceEvaluation) -> str:
    findings = "\n".join(_finding_block(finding) for finding in resource.findings)
    return f"""
    <details>
      <summary>{escape(resource.resource_type)}.{escape(resource.resource_name)}</summary>
      <p class=\"muted\">Line: {resource.line_number or 'n/a'}</p>
      <pre>{escape(resource.normalized_text)}</pre>
      {findings}
    </details>
    """


def _finding_block(finding: Finding) -> str:
    remediation = f"<p><strong>Remediation:</strong> {escape(finding.remediation)}</p>" if finding.remediation else ""
    proof = f"<pre>{escape(finding.proof)}</pre>" if finding.proof else ""
    return f"""
    <div class=\"finding\">
      <span class=\"badge {escape(finding.status)}\">{escape(finding.status)}</span>
      <span class=\"badge\">{escape(finding.severity)}</span>
      <h4>{escape(finding.rule_id)} — {escape(finding.title)}</h4>
      <p>{escape(finding.message)}</p>
      {remediation}
      {proof}
    </div>
    """


def _donut(score: int) -> str:
    circumference = 2 * 3.14159 * 54
    filled = circumference * (score / 100)
    return f"""
    <svg width=\"160\" height=\"160\" viewBox=\"0 0 160 160\" role=\"img\" aria-label=\"Compliance score {score}%\">
      <circle cx=\"80\" cy=\"80\" r=\"54\" fill=\"none\" stroke=\"#1e293b\" stroke-width=\"16\" />
      <circle cx=\"80\" cy=\"80\" r=\"54\" fill=\"none\" stroke=\"#38bdf8\" stroke-width=\"16\"
              stroke-dasharray=\"{filled:.2f} {circumference:.2f}\" transform=\"rotate(-90 80 80)\" stroke-linecap=\"round\" />
      <text x=\"80\" y=\"86\" text-anchor=\"middle\" font-size=\"28\" fill=\"#e5e7eb\" font-weight=\"700\">{score}%</text>
    </svg>
    """
