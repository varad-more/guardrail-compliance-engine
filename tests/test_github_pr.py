"""Tests for GitHub PR comment builder and diff CLI command."""
from __future__ import annotations

import asyncio
from pathlib import Path

from typer.testing import CliRunner

from guardrail_compliance.cli import app
from guardrail_compliance.core.engine import ComplianceEngine
from guardrail_compliance.reporting.github_pr import build_pr_comments, build_summary_comment
from guardrail_compliance.utils.config import EngineConfig

runner = CliRunner()


def _engine(project_root: Path, policies: list[str]) -> ComplianceEngine:
    return ComplianceEngine(
        EngineConfig(policy_dir=project_root / "policies", selected_policies=policies, use_bedrock=False)
    )


# ---------------------------------------------------------------------------
# build_pr_comments
# ---------------------------------------------------------------------------

def test_build_pr_comments_only_for_failures(project_root: Path):
    result = asyncio.run(_engine(project_root, ["soc2-basic"]).scan(
        project_root / "examples/terraform/noncompliant-s3.tf"
    ))
    comments = build_pr_comments([result])
    assert len(comments) > 0
    for c in comments:
        assert "path" in c
        assert "line" in c
        assert "body" in c


def test_build_pr_comments_empty_for_compliant(project_root: Path):
    result = asyncio.run(_engine(project_root, ["soc2-basic"]).scan(
        project_root / "examples/terraform/compliant-s3.tf"
    ))
    comments = build_pr_comments([result])
    assert comments == []


# ---------------------------------------------------------------------------
# build_summary_comment
# ---------------------------------------------------------------------------

def test_build_summary_comment_markdown(project_root: Path):
    result = asyncio.run(_engine(project_root, ["soc2-basic"]).scan(
        project_root / "examples/terraform/noncompliant-s3.tf"
    ))
    summary = build_summary_comment([result])
    assert "## GuardRail Compliance Report" in summary
    assert "Failures" in summary
    assert "Score" in summary


def test_build_summary_comment_no_failures(project_root: Path):
    result = asyncio.run(_engine(project_root, ["soc2-basic"]).scan(
        project_root / "examples/terraform/compliant-s3.tf"
    ))
    summary = build_summary_comment([result])
    assert "## GuardRail Compliance Report" in summary
    assert "Failed:** 0" in summary


# ---------------------------------------------------------------------------
# diff CLI command
# ---------------------------------------------------------------------------

def test_diff_command_no_changes(project_root: Path):
    result = runner.invoke(app, [
        "diff", str(project_root),
        "--ref", "HEAD",
        "--policy", "soc2-basic",
        "--policy-dir", str(project_root / "policies"),
        "--no-bedrock",
    ])
    assert result.exit_code == 0
    # Either no changes or a normal scan summary
    assert "No IaC files changed" in result.stdout or "Files:" in result.stdout


def test_diff_command_with_ref(project_root: Path):
    result = runner.invoke(app, [
        "diff", str(project_root),
        "--ref", "HEAD~1",
        "--policy", "soc2-basic",
        "--policy-dir", str(project_root / "policies"),
        "--no-bedrock",
    ])
    # Should succeed regardless of whether there are changes
    assert result.exit_code == 0
