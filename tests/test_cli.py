from pathlib import Path

from typer.testing import CliRunner

from guardrail_compliance.cli import app

runner = CliRunner()


def test_policy_list_command(project_root: Path) -> None:
    result = runner.invoke(app, ["policy", "list", "--policy-dir", str(project_root / "policies")])

    assert result.exit_code == 0
    assert "soc2-basic" in result.stdout


def test_scan_command_json_output(project_root: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            str(project_root / "examples/terraform/noncompliant-s3.tf"),
            "--policy",
            "soc2-basic",
            "--policy-dir",
            str(project_root / "policies"),
            "--no-bedrock",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert '"resource_type": "aws_s3_bucket"' in result.stdout
    assert '"normalized_facts"' in result.stdout


def test_scan_command_explain_output(project_root: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            str(project_root / "examples/terraform/noncompliant-s3.tf"),
            "--policy",
            "soc2-basic",
            "--policy-dir",
            str(project_root / "policies"),
            "--no-bedrock",
            "--explain",
        ],
    )

    assert result.exit_code == 0
    assert "Normalized narrative" in result.stdout
    assert "ssh_open_to_world" in result.stdout
