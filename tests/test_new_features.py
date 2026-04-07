"""Tests for new features: inline suppression, RDS backup check, severity threshold,
multi-framework dispatch, and diff-aware scanning helpers."""
from __future__ import annotations

import asyncio
from pathlib import Path

from typer.testing import CliRunner

from guardrail_compliance.cli import _has_failures_at_threshold, app
from guardrail_compliance.core.engine import ComplianceEngine
from guardrail_compliance.core.models import Finding, ResourceEvaluation, ScanResult
from guardrail_compliance.parsers.base import parse_suppressions
from guardrail_compliance.utils.config import EngineConfig

runner = CliRunner()


# ---------------------------------------------------------------------------
# parse_suppressions unit tests
# ---------------------------------------------------------------------------


class TestParseSuppressions:
    def test_bare_ignore_returns_wildcard(self):
        text = '# guardrail:ignore\nresource "aws_s3_bucket" "x" {}'
        assert parse_suppressions(text) == {"*"}

    def test_specific_rules(self):
        text = "# guardrail:ignore SOC2-ENC-001, SOC2-LOG-001\n..."
        assert parse_suppressions(text) == {"SOC2-ENC-001", "SOC2-LOG-001"}

    def test_case_insensitive(self):
        text = "# Guardrail:Ignore SOC2-ENC-001\n..."
        assert parse_suppressions(text) == {"SOC2-ENC-001"}

    def test_no_match(self):
        text = 'resource "aws_s3_bucket" "x" {}'
        assert parse_suppressions(text) == set()

    def test_multiple_ignore_lines(self):
        text = "# guardrail:ignore SOC2-ENC-001\n# guardrail:ignore SOC2-LOG-001\n..."
        assert parse_suppressions(text) == {"SOC2-ENC-001", "SOC2-LOG-001"}


# ---------------------------------------------------------------------------
# Inline suppression integration test
# ---------------------------------------------------------------------------


def test_suppression_skips_rules(project_root: Path, tmp_path: Path):
    """A resource with # guardrail:ignore SOC2-ENC-001 should not produce that finding."""
    tf = tmp_path / "suppressed.tf"
    tf.write_text(
        '# guardrail:ignore SOC2-ENC-001\n'
        'resource "aws_s3_bucket" "suppressed" {\n'
        '  bucket = "suppressed-bucket"\n'
        '  acl    = "private"\n'
        "}\n",
        encoding="utf-8",
    )

    engine = ComplianceEngine(
        EngineConfig(policy_dir=project_root / "policies", selected_policies=["soc2-basic"], use_bedrock=False)
    )
    result = asyncio.run(engine.scan(tf))

    rule_ids = {f.rule_id for r in result.resources for f in r.findings}
    assert "SOC2-ENC-001" not in rule_ids
    # Other rules should still fire
    assert "SOC2-LOG-001" in rule_ids


def test_suppress_all_skips_all_rules(project_root: Path, tmp_path: Path):
    """A resource with bare # guardrail:ignore should produce no findings."""
    tf = tmp_path / "suppress_all.tf"
    tf.write_text(
        '# guardrail:ignore\n'
        'resource "aws_s3_bucket" "ignored" {\n'
        '  bucket = "ignored-bucket"\n'
        "}\n",
        encoding="utf-8",
    )

    engine = ComplianceEngine(
        EngineConfig(policy_dir=project_root / "policies", selected_policies=["soc2-basic"], use_bedrock=False)
    )
    result = asyncio.run(engine.scan(tf))

    findings = [f for r in result.resources for f in r.findings]
    assert findings == []


# ---------------------------------------------------------------------------
# RDS backup checker
# ---------------------------------------------------------------------------


def test_rds_backup_check_passes_with_retention(project_root: Path, tmp_path: Path):
    tf = tmp_path / "rds_backup.tf"
    tf.write_text(
        'resource "aws_db_instance" "backed_up" {\n'
        '  identifier              = "backed-up-db"\n'
        '  engine                  = "postgres"\n'
        '  instance_class          = "db.t3.micro"\n'
        "  storage_encrypted       = true\n"
        '  kms_key_id              = "arn:aws:kms:us-east-1:123:key/abc"\n'
        "  backup_retention_period = 7\n"
        "}\n",
        encoding="utf-8",
    )

    engine = ComplianceEngine(
        EngineConfig(policy_dir=project_root / "policies", selected_policies=["hipaa-basic"], use_bedrock=False)
    )
    result = asyncio.run(engine.scan(tf))

    bkp_findings = [f for r in result.resources for f in r.findings if f.rule_id == "HIPAA-BKP-001"]
    assert bkp_findings
    assert bkp_findings[0].status == "PASS"


def test_rds_backup_check_fails_without_retention(project_root: Path, tmp_path: Path):
    tf = tmp_path / "rds_no_backup.tf"
    tf.write_text(
        'resource "aws_db_instance" "no_backup" {\n'
        '  identifier         = "no-backup-db"\n'
        '  engine             = "postgres"\n'
        '  instance_class     = "db.t3.micro"\n'
        "  storage_encrypted  = true\n"
        '  kms_key_id         = "arn:aws:kms:us-east-1:123:key/abc"\n'
        "}\n",
        encoding="utf-8",
    )

    engine = ComplianceEngine(
        EngineConfig(policy_dir=project_root / "policies", selected_policies=["hipaa-basic"], use_bedrock=False)
    )
    result = asyncio.run(engine.scan(tf))

    bkp_findings = [f for r in result.resources for f in r.findings if f.rule_id == "HIPAA-BKP-001"]
    assert bkp_findings
    assert bkp_findings[0].status == "FAIL"


# ---------------------------------------------------------------------------
# Multi-framework dispatch (all policies evaluate the same file)
# ---------------------------------------------------------------------------


def test_multi_framework_dispatch(project_root: Path):
    """All four policy packs should produce findings for the noncompliant S3 example."""
    all_policies = ["soc2-basic", "cis-aws-foundations", "pci-dss-basic", "hipaa-basic"]
    engine = ComplianceEngine(
        EngineConfig(policy_dir=project_root / "policies", selected_policies=all_policies, use_bedrock=False)
    )

    result = asyncio.run(engine.scan(project_root / "examples/terraform/noncompliant-s3.tf"))

    rule_ids = {f.rule_id for r in result.resources for f in r.findings}
    # Should have rules from each framework
    assert any(rid.startswith("SOC2-") for rid in rule_ids)
    assert any(rid.startswith("CIS-") for rid in rule_ids)
    assert any(rid.startswith("PCI-") for rid in rule_ids)
    assert any(rid.startswith("HIPAA-") for rid in rule_ids)


# ---------------------------------------------------------------------------
# Severity threshold helper
# ---------------------------------------------------------------------------


class TestHasFailuresAtThreshold:
    def _make_results(self, severities: list[str]) -> list[ScanResult]:
        findings = [
            Finding(rule_id=f"R{i}", title="t", severity=sev, status="FAIL", message="m")
            for i, sev in enumerate(severities)
        ]
        return [
            ScanResult(
                file_path=Path("test.tf"),
                parser="Test",
                resources=[
                    ResourceEvaluation(
                        resource_type="aws_s3_bucket",
                        resource_name="x",
                        file_path=Path("test.tf"),
                        line_number=1,
                        normalized_text="",
                        findings=findings,
                    )
                ],
            )
        ]

    def test_low_threshold_matches_low(self):
        assert _has_failures_at_threshold(self._make_results(["LOW"]), "LOW")

    def test_high_threshold_skips_low(self):
        assert not _has_failures_at_threshold(self._make_results(["LOW"]), "HIGH")

    def test_high_threshold_matches_critical(self):
        assert _has_failures_at_threshold(self._make_results(["CRITICAL"]), "HIGH")

    def test_empty_results(self):
        assert not _has_failures_at_threshold([], "LOW")


# ---------------------------------------------------------------------------
# CLI: severity threshold flag
# ---------------------------------------------------------------------------


def test_scan_fail_on_findings_respects_severity_threshold(project_root: Path, tmp_path: Path):
    """--severity-threshold HIGH should ignore MEDIUM-only failures."""
    # Create a file that only triggers SOC2-LOG-001 (MEDIUM severity).
    tf = tmp_path / "medium_only.tf"
    tf.write_text(
        '# guardrail:ignore SOC2-ENC-001, SOC2-NET-001\n'
        'resource "aws_s3_bucket" "logs" {\n'
        '  bucket = "medium-only"\n'
        '  acl    = "private"\n'
        '  server_side_encryption_configuration {\n'
        '    rule {\n'
        '      apply_server_side_encryption_by_default {\n'
        '        sse_algorithm = "AES256"\n'
        '      }\n'
        '    }\n'
        '  }\n'
        "}\n",
        encoding="utf-8",
    )

    # With HIGH threshold, MEDIUM findings should NOT cause exit code 1.
    result = runner.invoke(
        app,
        [
            "scan", str(tf),
            "--policy", "soc2-basic",
            "--policy-dir", str(project_root / "policies"),
            "--no-bedrock",
            "--fail-on-findings",
            "--severity-threshold", "HIGH",
        ],
    )
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# CLI: changed-only (with no actual changes, should short-circuit)
# ---------------------------------------------------------------------------


def test_scan_changed_only_no_changes(project_root: Path):
    """--changed-only HEAD should report nothing changed (HEAD vs HEAD = empty diff)."""
    result = runner.invoke(
        app,
        [
            "scan",
            str(project_root),
            "--policy", "soc2-basic",
            "--policy-dir", str(project_root / "policies"),
            "--no-bedrock",
            "--changed-only", "HEAD",
        ],
    )
    assert result.exit_code == 0
    # When HEAD vs HEAD yields no diff, we get the short-circuit message.
    # When the working tree has uncommitted changes, git diff HEAD returns them
    # and we get a normal scan summary instead.  Both are valid outcomes.
    assert "No IaC files changed" in result.stdout or "Files:" in result.stdout


# ---------------------------------------------------------------------------
# Compliant file produces all PASS
# ---------------------------------------------------------------------------


def test_compliant_s3_passes_all_rules(project_root: Path):
    engine = ComplianceEngine(
        EngineConfig(policy_dir=project_root / "policies", selected_policies=["soc2-basic"], use_bedrock=False)
    )
    result = asyncio.run(engine.scan(project_root / "examples/terraform/compliant-s3.tf"))

    statuses = [f.status for r in result.resources for f in r.findings]
    assert statuses  # should have findings
    assert all(s == "PASS" for s in statuses)


def test_compliant_rds_passes_encryption(project_root: Path):
    engine = ComplianceEngine(
        EngineConfig(policy_dir=project_root / "policies", selected_policies=["soc2-basic"], use_bedrock=False)
    )
    result = asyncio.run(engine.scan(project_root / "examples/terraform/compliant-rds.tf"))

    enc_findings = [f for r in result.resources for f in r.findings if "ENC" in f.rule_id]
    assert enc_findings
    assert all(f.status == "PASS" for f in enc_findings)
