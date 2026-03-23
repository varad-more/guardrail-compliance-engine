import asyncio
from pathlib import Path

from guardrail_compliance.core.engine import ComplianceEngine
from guardrail_compliance.utils.config import EngineConfig


def test_engine_finds_failures_in_noncompliant_example(project_root: Path) -> None:
    engine = ComplianceEngine(
        EngineConfig(policy_dir=project_root / "policies", selected_policies=["soc2-basic"], use_bedrock=False)
    )

    result = asyncio.run(engine.scan(project_root / "examples/terraform/noncompliant-s3.tf"))

    statuses = [finding.status for resource in result.resources for finding in resource.findings]
    assert "FAIL" in statuses
