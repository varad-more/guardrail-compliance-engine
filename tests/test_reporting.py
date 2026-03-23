import asyncio
from pathlib import Path

from guardrail_compliance.core.engine import ComplianceEngine
from guardrail_compliance.reporting.html_report import build_html_report
from guardrail_compliance.reporting.sarif import build_sarif_report
from guardrail_compliance.utils.config import EngineConfig


def test_reporting_outputs_are_generated(project_root: Path) -> None:
    engine = ComplianceEngine(
        EngineConfig(policy_dir=project_root / "policies", selected_policies=["soc2-basic"], use_bedrock=False)
    )
    results = [asyncio.run(engine.scan(project_root / "examples/terraform/noncompliant-s3.tf"))]

    sarif = build_sarif_report(results)
    html = build_html_report(results)

    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]
    assert "GuardRail Compliance Report" in html
    assert "SOC2-ENC-001" in html
