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



def test_scan_command_sarif_output_to_file(project_root: Path, tmp_path: Path) -> None:
    output = tmp_path / "results.sarif"
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
            "sarif",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert output.exists()
    assert '"version": "2.1.0"' in output.read_text(encoding="utf-8")



def test_audit_command_matches_framework(project_root: Path) -> None:
    result = runner.invoke(
        app,
        [
            "audit",
            str(project_root / "examples/cloudformation/noncompliant-stack.yaml"),
            "--frameworks",
            "soc2",
            "--policy-dir",
            str(project_root / "policies"),
            "--no-bedrock",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert '"AWS::S3::Bucket"' in result.stdout



def test_policy_sync_command_handles_no_bindings(project_root: Path) -> None:
    result = runner.invoke(app, ["policy", "sync", "--policy-dir", str(project_root / "policies")])

    assert result.exit_code == 0
    assert "No policies were synced" in result.stdout


def test_ar_cli_commands(monkeypatch, tmp_path: Path) -> None:
    class StubManager:
        def __init__(self, *args, **kwargs):
            pass

        def list_automated_reasoning_policies(self):
            class Item:
                name = "demo"
                version = "DRAFT"
                policy_arn = "arn:demo"
                policy_id = "id-1"

            return [Item()]

        def create_automated_reasoning_policy(self, **kwargs):
            return "arn:new"

        def start_automated_reasoning_ingest_build_from_file(self, **kwargs):
            return "wf-1"

        def get_automated_reasoning_policy_build_workflow(self, **kwargs):
            return {"policyArn": "arn:new", "buildWorkflowId": "wf-1", "status": "COMPLETED"}

        def create_automated_reasoning_policy_version_from_latest(self, **kwargs):
            return "1"

        def create_automated_reasoning_policy_version(self, **kwargs):
            return "2"

        def export_automated_reasoning_policy_version(self, policy_version_arn):
            return {"version": "1.0", "rules": [], "variables": [], "types": []}

    monkeypatch.setattr("guardrail_compliance.cli.PolicyManager", StubManager)

    source = tmp_path / "source.txt"
    source.write_text("if this then that", encoding="utf-8")
    out = tmp_path / "export.json"

    list_result = runner.invoke(app, ["policy", "ar-list"])
    create_result = runner.invoke(app, ["policy", "ar-create", "--name", "demo", "--source-file", str(source)])
    status_result = runner.invoke(
        app,
        ["policy", "ar-build-status", "--policy-arn", "arn:new", "--workflow-id", "wf-1"],
    )
    version_result = runner.invoke(app, ["policy", "ar-version", "--policy-arn", "arn:new"])
    export_result = runner.invoke(app, ["policy", "ar-export", "--policy-version-arn", "arn:new:1", "--output", str(out)])

    assert list_result.exit_code == 0
    assert "demo" in list_result.stdout
    assert create_result.exit_code == 0
    assert "Created AR policy" in create_result.stdout
    assert status_result.exit_code == 0
    assert "COMPLETED" in status_result.stdout
    assert version_result.exit_code == 0
    assert "Created policy version" in version_result.stdout
    assert export_result.exit_code == 0
    assert out.exists()
