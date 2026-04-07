"""Tests for config file auto-loading."""
from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from guardrail_compliance.cli import app
from guardrail_compliance.utils.config import EngineConfig, find_config_file

runner = CliRunner()


def test_from_yaml_loads_all_fields(tmp_path: Path):
    cfg_path = tmp_path / ".guardrail.yaml"
    cfg_path.write_text(yaml.safe_dump({
        "region": "eu-west-1",
        "policies": ["hipaa-basic"],
        "policy_dir": "my-policies",
        "use_bedrock": False,
    }), encoding="utf-8")

    data = EngineConfig.from_yaml(cfg_path)
    assert data["region"] == "eu-west-1"
    assert data["policies"] == ["hipaa-basic"]
    assert data["use_bedrock"] is False


def test_from_yaml_missing_file_returns_empty():
    data = EngineConfig.from_yaml(Path("/nonexistent/.guardrail.yaml"))
    assert data == {}


def test_find_config_file_discovers_yaml(tmp_path: Path):
    cfg = tmp_path / ".guardrail.yaml"
    cfg.write_text("region: us-west-2\n", encoding="utf-8")
    found = find_config_file(tmp_path)
    assert found == cfg


def test_find_config_file_returns_none_when_absent(tmp_path: Path):
    found = find_config_file(tmp_path)
    assert found is None


def test_cli_scan_uses_config_file_policies(project_root: Path, tmp_path: Path, monkeypatch):
    """Config file policies are used when --policy is not passed."""
    cfg = tmp_path / ".guardrail.yaml"
    cfg.write_text(yaml.safe_dump({
        "policies": ["soc2-basic"],
        "use_bedrock": False,
    }), encoding="utf-8")
    # Monkeypatch find_config_file to return our temp config
    monkeypatch.setattr("guardrail_compliance.cli.find_config_file", lambda: cfg)

    result = runner.invoke(app, [
        "scan",
        str(project_root / "examples/terraform/noncompliant-s3.tf"),
        "--policy-dir", str(project_root / "policies"),
        "--no-bedrock",
        "--format", "json",
    ])
    assert result.exit_code == 0
    assert '"SOC2-ENC-001"' in result.stdout
