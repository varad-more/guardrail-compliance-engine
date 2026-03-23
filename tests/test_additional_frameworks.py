import asyncio
from pathlib import Path

from guardrail_compliance.core.engine import ComplianceEngine
from guardrail_compliance.utils.config import EngineConfig



def test_cis_policy_evaluates_weak_password_policy(project_root: Path) -> None:
    engine = ComplianceEngine(
        EngineConfig(policy_dir=project_root / "policies", selected_policies=["cis-aws-foundations"], use_bedrock=False)
    )

    result = asyncio.run(engine.scan(project_root / "examples/terraform/noncompliant-iam-password-policy.tf"))

    findings = [finding for resource in result.resources for finding in resource.findings]
    assert findings
    assert any(finding.status == "FAIL" for finding in findings)
    assert any(finding.rule_id == "CIS-IAM-001" for finding in findings)



def test_pci_policy_reuses_existing_security_group_logic(project_root: Path) -> None:
    engine = ComplianceEngine(
        EngineConfig(policy_dir=project_root / "policies", selected_policies=["pci-dss-basic"], use_bedrock=False)
    )

    result = asyncio.run(engine.scan(project_root / "examples/terraform/noncompliant-s3.tf"))

    findings = [finding for resource in result.resources for finding in resource.findings]
    assert any(finding.rule_id == "PCI-NET-001" and finding.status == "FAIL" for finding in findings)
