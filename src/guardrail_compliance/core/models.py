from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    status: str
    message: str
    proof: str | None = None
    remediation: str | None = None
    source: str = "local"
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ComplianceResult:
    action: str
    findings: list[Finding] = field(default_factory=list)
    raw_response: dict[str, Any] = field(default_factory=dict)
    usage: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class GuardrailInfo:
    name: str
    guardrail_id: str
    version: str = "DRAFT"
    automated_reasoning_policy_arns: list[str] = field(default_factory=list)
    cross_region_profile: str | None = None
    arn: str | None = None
    status: str | None = None
    tags: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class ResourceEvaluation:
    resource_type: str
    resource_name: str
    file_path: Path
    line_number: int | None
    normalized_text: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not any(f.status == "FAIL" for f in self.findings)


@dataclass(slots=True)
class ScanResult:
    file_path: Path
    parser: str
    resources: list[ResourceEvaluation] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return sum(len(resource.findings) for resource in self.resources)

    @property
    def failed_findings(self) -> int:
        return sum(1 for resource in self.resources for finding in resource.findings if finding.status == "FAIL")

    @property
    def passed_findings(self) -> int:
        return sum(1 for resource in self.resources for finding in resource.findings if finding.status == "PASS")

    @property
    def has_failures(self) -> bool:
        return self.failed_findings > 0 or bool(self.errors)
