"""Tests for auto-remediation snippet attachment."""
from __future__ import annotations

import asyncio
from pathlib import Path

from guardrail_compliance.core.engine import ComplianceEngine
from guardrail_compliance.remediation.snippets import get_snippet
from guardrail_compliance.utils.config import EngineConfig


def _engine(project_root: Path, policies: list[str]) -> ComplianceEngine:
    return ComplianceEngine(
        EngineConfig(policy_dir=project_root / "policies", selected_policies=policies, use_bedrock=False)
    )


def _findings(result, rule_id: str):
    return [f for r in result.resources for f in r.findings if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# Unit tests for the snippet registry
# ---------------------------------------------------------------------------

def test_get_snippet_known_checker():
    snippet = get_snippet("_check_s3_encryption", "aws_s3_bucket")
    assert snippet is not None
    assert "encryption" in snippet.lower() or "sse" in snippet.lower()


def test_get_snippet_wildcard_k8s():
    snippet = get_snippet("_check_k8s_privileged", "Pod")
    assert snippet is not None
    assert "privileged" in snippet


def test_get_snippet_unknown_checker():
    assert get_snippet("_check_nonexistent", "aws_s3_bucket") is None


def test_get_snippet_unknown_resource_type():
    assert get_snippet("_check_s3_encryption", "aws_lambda_function") is None


# ---------------------------------------------------------------------------
# Integration: snippets attached to FAIL findings
# ---------------------------------------------------------------------------

def test_fail_finding_has_snippet(project_root: Path):
    result = asyncio.run(_engine(project_root, ["soc2-basic"]).scan(
        project_root / "examples/terraform/noncompliant-s3.tf"
    ))
    fails = [f for r in result.resources for f in r.findings if f.status == "FAIL" and f.remediation_snippet]
    assert fails, "At least one FAIL finding should have a remediation snippet"


def test_pass_finding_has_no_snippet(project_root: Path):
    result = asyncio.run(_engine(project_root, ["soc2-basic"]).scan(
        project_root / "examples/terraform/compliant-s3.tf"
    ))
    with_snippets = [f for r in result.resources for f in r.findings if f.remediation_snippet]
    assert not with_snippets, "PASS findings should not have remediation snippets"


def test_k8s_fail_has_snippet(project_root: Path):
    result = asyncio.run(_engine(project_root, ["k8s-security"]).scan(
        project_root / "examples/kubernetes/noncompliant-deployment.yaml"
    ))
    fails = [f for r in result.resources for f in r.findings if f.status == "FAIL" and f.remediation_snippet]
    assert fails, "K8s FAIL findings should have remediation snippets"


def test_ebs_fail_has_snippet(project_root: Path):
    result = asyncio.run(_engine(project_root, ["cis-aws-foundations"]).scan(
        project_root / "examples/terraform/aws-services.tf"
    ))
    ebs_fails = [f for f in _findings(result, "CIS-EBS-001") if f.status == "FAIL"]
    assert ebs_fails and ebs_fails[0].remediation_snippet
    assert "encrypted" in ebs_fails[0].remediation_snippet.lower()
