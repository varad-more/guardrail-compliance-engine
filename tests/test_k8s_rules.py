"""Tests for Kubernetes compliance rules (k8s-security policy pack)."""
from __future__ import annotations

import asyncio
from pathlib import Path

import yaml

from guardrail_compliance.core.engine import ComplianceEngine
from guardrail_compliance.utils.config import EngineConfig


def _engine(project_root: Path) -> ComplianceEngine:
    return ComplianceEngine(
        EngineConfig(policy_dir=project_root / "policies", selected_policies=["k8s-security"], use_bedrock=False)
    )


def _write_pod(tmp_path: Path, name: str, pod_spec: dict) -> Path:
    doc = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": pod_spec}
    p = tmp_path / f"{name}.yaml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return p


def _findings(result, rule_id: str):
    return [f for r in result.resources for f in r.findings if f.rule_id == rule_id]


# ---------------------------------------------------------------------------
# K8S-SEC-001: No privileged containers
# ---------------------------------------------------------------------------

def test_privileged_container_fails(project_root: Path, tmp_path: Path):
    p = _write_pod(tmp_path, "priv", {
        "containers": [{"name": "app", "image": "nginx", "securityContext": {"privileged": True}}],
    })
    result = asyncio.run(_engine(project_root).scan(p))
    findings = _findings(result, "K8S-SEC-001")
    assert findings and findings[0].status == "FAIL"


def test_non_privileged_passes(project_root: Path, tmp_path: Path):
    p = _write_pod(tmp_path, "safe", {
        "containers": [{"name": "app", "image": "nginx", "securityContext": {"privileged": False}}],
    })
    result = asyncio.run(_engine(project_root).scan(p))
    findings = _findings(result, "K8S-SEC-001")
    assert findings and findings[0].status == "PASS"


# ---------------------------------------------------------------------------
# K8S-SEC-002: Must run as non-root
# ---------------------------------------------------------------------------

def test_run_as_root_fails(project_root: Path, tmp_path: Path):
    p = _write_pod(tmp_path, "root", {
        "containers": [{"name": "app", "image": "nginx"}],
    })
    result = asyncio.run(_engine(project_root).scan(p))
    findings = _findings(result, "K8S-SEC-002")
    assert findings and findings[0].status == "FAIL"


def test_run_as_non_root_passes(project_root: Path, tmp_path: Path):
    p = _write_pod(tmp_path, "nonroot", {
        "securityContext": {"runAsNonRoot": True},
        "containers": [{"name": "app", "image": "nginx"}],
    })
    result = asyncio.run(_engine(project_root).scan(p))
    findings = _findings(result, "K8S-SEC-002")
    assert findings and findings[0].status == "PASS"


# ---------------------------------------------------------------------------
# K8S-SEC-003: Resource limits required
# ---------------------------------------------------------------------------

def test_missing_resource_limits_fails(project_root: Path, tmp_path: Path):
    p = _write_pod(tmp_path, "nolimits", {
        "containers": [{"name": "app", "image": "nginx"}],
    })
    result = asyncio.run(_engine(project_root).scan(p))
    findings = _findings(result, "K8S-SEC-003")
    assert findings and findings[0].status == "FAIL"


def test_resource_limits_present_passes(project_root: Path, tmp_path: Path):
    p = _write_pod(tmp_path, "limited", {
        "containers": [{"name": "app", "image": "nginx",
                        "resources": {"limits": {"cpu": "500m", "memory": "128Mi"}}}],
    })
    result = asyncio.run(_engine(project_root).scan(p))
    findings = _findings(result, "K8S-SEC-003")
    assert findings and findings[0].status == "PASS"


# ---------------------------------------------------------------------------
# K8S-SEC-004: No host namespace sharing
# ---------------------------------------------------------------------------

def test_host_network_fails(project_root: Path, tmp_path: Path):
    p = _write_pod(tmp_path, "hostnet", {
        "hostNetwork": True,
        "containers": [{"name": "app", "image": "nginx"}],
    })
    result = asyncio.run(_engine(project_root).scan(p))
    findings = _findings(result, "K8S-SEC-004")
    assert findings and findings[0].status == "FAIL"
    assert "host_network" in findings[0].message


def test_no_host_namespaces_passes(project_root: Path, tmp_path: Path):
    p = _write_pod(tmp_path, "isolated", {
        "containers": [{"name": "app", "image": "nginx"}],
    })
    result = asyncio.run(_engine(project_root).scan(p))
    findings = _findings(result, "K8S-SEC-004")
    assert findings and findings[0].status == "PASS"


# ---------------------------------------------------------------------------
# K8S-SEC-005: Probes required
# ---------------------------------------------------------------------------

def test_missing_probes_fails(project_root: Path, tmp_path: Path):
    p = _write_pod(tmp_path, "noprobes", {
        "containers": [{"name": "app", "image": "nginx"}],
    })
    result = asyncio.run(_engine(project_root).scan(p))
    findings = _findings(result, "K8S-SEC-005")
    assert findings and findings[0].status == "FAIL"


def test_probes_present_passes(project_root: Path, tmp_path: Path):
    p = _write_pod(tmp_path, "probed", {
        "containers": [{"name": "app", "image": "nginx",
                        "livenessProbe": {"httpGet": {"path": "/", "port": 80}},
                        "readinessProbe": {"httpGet": {"path": "/", "port": 80}}}],
    })
    result = asyncio.run(_engine(project_root).scan(p))
    findings = _findings(result, "K8S-SEC-005")
    assert findings and findings[0].status == "PASS"


# ---------------------------------------------------------------------------
# Integration: noncompliant deployment example
# ---------------------------------------------------------------------------

def test_noncompliant_deployment_triggers_failures(project_root: Path):
    result = asyncio.run(_engine(project_root).scan(
        project_root / "examples/kubernetes/noncompliant-deployment.yaml"
    ))
    rule_ids = {f.rule_id for r in result.resources for f in r.findings if f.status == "FAIL"}
    assert "K8S-SEC-001" in rule_ids  # privileged
    assert "K8S-SEC-002" in rule_ids  # run as root
    assert "K8S-SEC-004" in rule_ids  # host namespaces
