from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ..core.models import Finding, ResourceEvaluation, ScanResult


def build_sarif_report(results: Iterable[ScanResult]) -> dict[str, Any]:
    """Build a SARIF 2.1.0 report from scan results (for GitHub Security tab integration)."""
    rules: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

    for scan in results:
        for resource in scan.resources:
            for finding in resource.findings:
                rules.setdefault(finding.rule_id, _rule_descriptor(finding))
                sarif_results.append(_result(scan, resource, finding))

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GuardRail Compliance Engine",
                        "informationUri": "https://github.com/varad-more/guardrail-compliance-engine",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def _rule_descriptor(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.rule_id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.message},
        "properties": {
            "severity": finding.severity,
            "source": finding.source,
        },
    }


def _result(scan: ScanResult, resource: ResourceEvaluation, finding: Finding) -> dict[str, Any]:
    return {
        "ruleId": finding.rule_id,
        "level": _sarif_level(finding),
        "message": {"text": _message_text(resource, finding)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": str(scan.file_path)},
                    "region": {"startLine": resource.line_number or 1},
                },
                "logicalLocations": [
                    {
                        "fullyQualifiedName": f"{resource.resource_type}.{resource.resource_name}",
                        "name": resource.resource_name,
                        "kind": "resource",
                    }
                ],
            }
        ],
        "properties": {
            "resourceType": resource.resource_type,
            "resourceName": resource.resource_name,
            "severity": finding.severity,
            "source": finding.source,
        },
        **({"fixes": [{"description": {"text": "Suggested fix"},
                        "artifactChanges": [{"artifactLocation": {"uri": str(scan.file_path)},
                                             "replacements": [{"insertedContent": {"text": finding.remediation_snippet}}]}]}]}
           if finding.remediation_snippet else {}),
    }


def _sarif_level(finding: Finding) -> str:
    if finding.status == "PASS":
        return "note"
    return {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }.get(finding.severity.upper(), "warning")


def _message_text(resource: ResourceEvaluation, finding: Finding) -> str:
    parts = [
        f"{finding.title}: {finding.message}",
        f"Resource: {resource.resource_type}.{resource.resource_name}",
    ]
    if finding.remediation:
        parts.append(f"Remediation: {finding.remediation}")
    if finding.proof:
        parts.append(f"Proof: {finding.proof}")
    return "\n".join(parts)
