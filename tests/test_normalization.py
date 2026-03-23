import asyncio
from pathlib import Path

from guardrail_compliance.core.engine import ComplianceEngine
from guardrail_compliance.utils.config import EngineConfig


def test_normalized_facts_capture_s3_and_security_group_details(project_root: Path) -> None:
    engine = ComplianceEngine(
        EngineConfig(policy_dir=project_root / "policies", selected_policies=["soc2-basic"], use_bedrock=False)
    )

    result = asyncio.run(engine.scan(project_root / "examples/terraform/noncompliant-s3.tf"))

    bucket = next(resource for resource in result.resources if resource.resource_type == "aws_s3_bucket")
    security_group = next(resource for resource in result.resources if resource.resource_type == "aws_security_group")

    assert bucket.normalized_facts["acl"] == "public-read"
    assert bucket.normalized_facts["encryption_configured"] is False
    assert bucket.normalized_facts["public_access_block_present"] is False
    assert security_group.normalized_facts["ssh_open_to_world"] is True
    assert 22 in security_group.normalized_facts["public_ingress_ports"]
