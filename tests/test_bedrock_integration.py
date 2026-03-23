import asyncio
from pathlib import Path

import pytest

from guardrail_compliance.core.engine import ComplianceEngine
from guardrail_compliance.core.models import ComplianceResult
from guardrail_compliance.utils.config import EngineConfig


class DummyBedrockClient:
    calls = 0

    def __init__(self, *args, **kwargs):
        pass

    async def evaluate(self, content: str, content_type: str = "terraform") -> ComplianceResult:
        DummyBedrockClient.calls += 1
        return ComplianceResult(action="NONE", findings=[])


@pytest.mark.parametrize("example_name", ["compliant-s3.tf", "noncompliant-s3.tf"])
def test_engine_calls_bedrock_once_per_policy_per_resource(monkeypatch, tmp_path: Path, project_root: Path, example_name: str) -> None:
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    (policy_dir / "bedrock-test.yaml").write_text(
        """
name: bedrock-test
version: \"0.1.0\"
framework: Test
guardrail_id: gr-test
rules:
  - id: BEDROCK-001
    title: First Bedrock-backed rule
    description: test
    severity: HIGH
    resource_types:
      - aws_s3_bucket
    constraint: first
  - id: BEDROCK-002
    title: Second Bedrock-backed rule
    description: test
    severity: HIGH
    resource_types:
      - aws_s3_bucket
    constraint: second
""".strip(),
        encoding="utf-8",
    )

    DummyBedrockClient.calls = 0
    monkeypatch.setattr("guardrail_compliance.core.engine.BedrockGuardrailClient", DummyBedrockClient)

    engine = ComplianceEngine(EngineConfig(policy_dir=policy_dir, selected_policies=["bedrock-test"], use_bedrock=True))
    result = asyncio.run(engine.scan(project_root / f"examples/terraform/{example_name}"))

    assert DummyBedrockClient.calls == 1
    bucket = next(resource for resource in result.resources if resource.resource_type == "aws_s3_bucket")
    assert len(bucket.findings) == 1
    assert bucket.findings[0].source == "bedrock"
