from pathlib import Path

from guardrail_compliance.policies.registry import PolicyRegistry


def test_policy_registry_loads_starter_policies(project_root: Path) -> None:
    registry = PolicyRegistry(project_root / "policies")

    policies = registry.load()

    assert "soc2-basic" in policies
    assert "hipaa-basic" in policies
    assert "pci-dss-basic" in policies
    assert "cis-aws-foundations" in policies
    assert len(policies["soc2-basic"].rules) >= 5
    assert len(policies["hipaa-basic"].rules) >= 5
    assert len(policies["pci-dss-basic"].rules) >= 5
    assert len(policies["cis-aws-foundations"].rules) >= 5



def test_default_policy_registry_loads_bundled_policies() -> None:
    registry = PolicyRegistry.default()

    policies = registry.load()

    assert "soc2-basic" in policies
    assert "hipaa-basic" in policies
    assert "pci-dss-basic" in policies
    assert "cis-aws-foundations" in policies
