from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..utils.exceptions import PolicyValidationError


@dataclass(slots=True)
class PolicyRule:
    id: str
    title: str
    description: str
    severity: str
    resource_types: list[str]
    constraint: str
    remediation: str = ""


@dataclass(slots=True)
class PolicyDefinition:
    name: str
    version: str
    framework: str
    description: str
    rules: list[PolicyRule] = field(default_factory=list)
    automated_reasoning_policy_arn: str | None = None
    guardrail_id: str | None = None
    guardrail_version: str = "DRAFT"
    confidence_threshold: float = 0.8
    cross_region_profile: str | None = "us.guardrail.v1:0"


class PolicyRegistry:
    """Loads, validates, and queries YAML policy definitions from a directory."""

    def __init__(self, policy_dir: Path) -> None:
        self.policy_dir = policy_dir
        self._policies: dict[str, PolicyDefinition] = {}

    def load(self) -> dict[str, PolicyDefinition]:
        self._policies = {}
        if not self.policy_dir.exists():
            raise PolicyValidationError(f"Policy directory does not exist: {self.policy_dir}")

        for path in sorted(self.policy_dir.glob("*.y*ml")):
            policy = self.load_policy(path)
            self._policies[policy.name] = policy
        return self._policies

    def load_policy(self, path: Path) -> PolicyDefinition:
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        self.validate_document(document, path)

        rules = [
            PolicyRule(
                id=str(rule["id"]),
                title=str(rule["title"]),
                description=str(rule.get("description", "")),
                severity=str(rule["severity"]).upper(),
                resource_types=[str(item) for item in rule["resource_types"]],
                constraint=str(rule["constraint"]),
                remediation=str(rule.get("remediation", "")),
            )
            for rule in document["rules"]
        ]

        return PolicyDefinition(
            name=str(document["name"]),
            version=str(document.get("version", "0.1.0")),
            framework=str(document.get("framework", document["name"])),
            description=str(document.get("description", "")),
            rules=rules,
            automated_reasoning_policy_arn=document.get("automated_reasoning_policy_arn"),
            guardrail_id=document.get("guardrail_id"),
            guardrail_version=str(document.get("guardrail_version", "DRAFT")),
            confidence_threshold=float(document.get("confidence_threshold", 0.8)),
            cross_region_profile=document.get("cross_region_profile", "us.guardrail.v1:0"),
        )

    def validate_document(self, document: dict[str, Any], path: Path | None = None) -> None:
        required_top_level = {"name", "rules"}
        missing = sorted(required_top_level - document.keys())
        if missing:
            location = f" in {path}" if path else ""
            raise PolicyValidationError(f"Missing required policy fields{location}: {', '.join(missing)}")

        if not isinstance(document["rules"], list) or not document["rules"]:
            raise PolicyValidationError("Policy rules must be a non-empty list")

        for index, rule in enumerate(document["rules"], start=1):
            for field_name in ("id", "title", "severity", "resource_types", "constraint"):
                if field_name not in rule:
                    raise PolicyValidationError(f"Rule #{index} missing field: {field_name}")
            if not isinstance(rule["resource_types"], list) or not rule["resource_types"]:
                raise PolicyValidationError(f"Rule #{index} must declare at least one resource type")

    def get(self, name: str) -> PolicyDefinition:
        if not self._policies:
            self.load()
        try:
            return self._policies[name]
        except KeyError as exc:
            raise PolicyValidationError(f"Unknown policy: {name}") from exc

    def all(self) -> list[PolicyDefinition]:
        if not self._policies:
            self.load()
        return list(self._policies.values())

    def match_rules(self, resource_type: str, selected_policies: list[str] | None = None) -> list[tuple[PolicyDefinition, PolicyRule]]:
        if not self._policies:
            self.load()

        allowed = set(selected_policies or self._policies.keys())
        matches: list[tuple[PolicyDefinition, PolicyRule]] = []
        for policy in self._policies.values():
            if policy.name not in allowed:
                continue
            for rule in policy.rules:
                if resource_type in rule.resource_types:
                    matches.append((policy, rule))
        return matches

    @classmethod
    def default(cls) -> PolicyRegistry:
        package_root = Path(__file__).resolve().parents[1]
        bundled_policy_dir = package_root / "policy_data"
        if bundled_policy_dir.exists():
            return cls(bundled_policy_dir)

        project_root = Path(__file__).resolve().parents[3]
        return cls(project_root / "policies")
