"""Tests for extended AWS resource coverage (CloudTrail, EBS, DynamoDB, VPC flow logs)."""
from __future__ import annotations

import asyncio
from pathlib import Path

from guardrail_compliance.core.engine import ComplianceEngine
from guardrail_compliance.utils.config import EngineConfig


def _engine(project_root: Path, policies: list[str]) -> ComplianceEngine:
    return ComplianceEngine(
        EngineConfig(policy_dir=project_root / "policies", selected_policies=policies, use_bedrock=False)
    )


def _findings(result, rule_id: str):
    return [f for r in result.resources for f in r.findings if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# CloudTrail
# ---------------------------------------------------------------------------

def test_cloudtrail_bad_fails(project_root: Path):
    engine = _engine(project_root, ["soc2-basic"])
    result = asyncio.run(engine.scan(project_root / "examples/terraform/aws-services.tf"))
    findings = _findings(result, "SOC2-LOG-002")
    bad = [f for f in findings if "bad" in (f.proof or "")]
    assert bad and bad[0].status == "FAIL"


def test_cloudtrail_good_passes(project_root: Path):
    engine = _engine(project_root, ["soc2-basic"])
    result = asyncio.run(engine.scan(project_root / "examples/terraform/aws-services.tf"))
    findings = _findings(result, "SOC2-LOG-002")
    good = [f for f in findings if "good" in (f.proof or "")]
    assert good and good[0].status == "PASS"


# ---------------------------------------------------------------------------
# EBS
# ---------------------------------------------------------------------------

def test_ebs_unencrypted_fails(project_root: Path):
    engine = _engine(project_root, ["cis-aws-foundations"])
    result = asyncio.run(engine.scan(project_root / "examples/terraform/aws-services.tf"))
    findings = _findings(result, "CIS-EBS-001")
    bad = [f for f in findings if f.status == "FAIL"]
    assert bad


def test_ebs_encrypted_passes(project_root: Path):
    engine = _engine(project_root, ["cis-aws-foundations"])
    result = asyncio.run(engine.scan(project_root / "examples/terraform/aws-services.tf"))
    findings = _findings(result, "CIS-EBS-001")
    good = [f for f in findings if f.status == "PASS"]
    assert good


# ---------------------------------------------------------------------------
# DynamoDB
# ---------------------------------------------------------------------------

def test_dynamodb_no_sse_fails(project_root: Path):
    engine = _engine(project_root, ["soc2-basic"])
    result = asyncio.run(engine.scan(project_root / "examples/terraform/aws-services.tf"))
    findings = _findings(result, "SOC2-ENC-004")
    bad = [f for f in findings if f.status == "FAIL"]
    assert bad


def test_dynamodb_with_sse_passes(project_root: Path):
    engine = _engine(project_root, ["soc2-basic"])
    result = asyncio.run(engine.scan(project_root / "examples/terraform/aws-services.tf"))
    findings = _findings(result, "SOC2-ENC-004")
    good = [f for f in findings if f.status == "PASS"]
    assert good


# ---------------------------------------------------------------------------
# VPC Flow Logs
# ---------------------------------------------------------------------------

def test_flow_log_no_destination_fails(project_root: Path):
    engine = _engine(project_root, ["cis-aws-foundations"])
    result = asyncio.run(engine.scan(project_root / "examples/terraform/aws-services.tf"))
    findings = _findings(result, "CIS-VPC-001")
    bad = [f for f in findings if f.status == "FAIL"]
    assert bad


def test_flow_log_with_destination_passes(project_root: Path):
    engine = _engine(project_root, ["cis-aws-foundations"])
    result = asyncio.run(engine.scan(project_root / "examples/terraform/aws-services.tf"))
    findings = _findings(result, "CIS-VPC-001")
    good = [f for f in findings if f.status == "PASS"]
    assert good
