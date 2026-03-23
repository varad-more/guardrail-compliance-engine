from pathlib import Path

from guardrail_compliance.policies.registry import PolicyRegistry


def test_policy_registry_loads_starter_policies(project_root: Path) -> None:
    registry = PolicyRegistry(project_root / "policies")

    policies = registry.load()

    assert "soc2-basic" in policies
    assert len(policies["soc2-basic"].rules) >= 5
