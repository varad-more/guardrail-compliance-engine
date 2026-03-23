from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .guardrail_client import BedrockGuardrailClient
from .models import Finding, ResourceEvaluation, ScanResult
from ..parsers import TerraformParser
from ..parsers.base import IaCParser, ResourceBlock
from ..policies.registry import PolicyDefinition, PolicyRegistry, PolicyRule
from ..utils.config import EngineConfig
from ..utils.exceptions import ParserError, PolicyValidationError


class ComplianceEngine:
    def __init__(self, config: EngineConfig) -> None:
        self.config = config
        project_root = Path(__file__).resolve().parents[3]
        policy_dir = config.resolve_policy_dir(project_root)
        self.policy_registry = PolicyRegistry(policy_dir)
        self.parsers: list[IaCParser] = [TerraformParser()]
        self._client_cache: dict[tuple[str, str], BedrockGuardrailClient] = {}

    async def scan(self, file_path: Path) -> ScanResult:
        parser = self._detect_parser(file_path)
        resources = parser.parse(file_path)
        selected = self.config.selected_policies or [policy.name for policy in self.policy_registry.all()]
        evaluations: list[ResourceEvaluation] = []

        for resource in resources:
            normalized = self._build_normalized_resource_text(resource)
            findings: list[Finding] = []
            matched_rules = self.policy_registry.match_rules(resource.resource_type, selected)
            for policy, rule in matched_rules:
                if self.config.use_bedrock and policy.guardrail_id:
                    findings.extend(await self._evaluate_with_bedrock(resource, normalized, policy))
                else:
                    findings.append(self._evaluate_locally(resource, rule, resources))
            evaluations.append(
                ResourceEvaluation(
                    resource_type=resource.resource_type,
                    resource_name=resource.resource_name,
                    file_path=resource.file_path,
                    line_number=resource.line_number,
                    normalized_text=normalized,
                    findings=findings,
                )
            )

        return ScanResult(file_path=file_path, parser=parser.__class__.__name__, resources=evaluations)

    async def scan_directory(self, dir_path: Path, recursive: bool = True) -> list[ScanResult]:
        pattern = "**/*" if recursive else "*"
        files = [path for path in sorted(dir_path.glob(pattern)) if path.is_file()]
        supported = [path for path in files if any(parser.supports(path) for parser in self.parsers)]
        results: list[ScanResult] = []
        for path in supported:
            results.append(await self.scan(path))
        return results

    def _detect_parser(self, file_path: Path) -> IaCParser:
        for parser in self.parsers:
            if parser.supports(file_path):
                return parser
        raise ParserError(f"No parser available for file: {file_path}")

    def _match_policies(self, resource_type: str) -> list[str]:
        return sorted({policy.name for policy, _ in self.policy_registry.match_rules(resource_type)})

    async def _evaluate_with_bedrock(
        self,
        resource: ResourceBlock,
        normalized_text: str,
        policy: PolicyDefinition,
    ) -> list[Finding]:
        client = self._client_cache.setdefault(
            (policy.guardrail_id or "", policy.guardrail_version),
            BedrockGuardrailClient(
                guardrail_id=policy.guardrail_id or "",
                guardrail_version=policy.guardrail_version,
                region=self.config.region,
            ),
        )
        compliance = await client.evaluate(normalized_text, content_type=resource.resource_type)
        if compliance.findings:
            return compliance.findings
        status = "PASS" if compliance.action == "NONE" else "WARN"
        return [
            Finding(
                rule_id=f"{policy.name.upper()}-NO-FINDINGS",
                title=f"{policy.name} automated reasoning result",
                severity="LOW",
                status=status,
                message=f"ApplyGuardrail returned action={compliance.action} with no explicit findings.",
                proof="No automated reasoning findings were returned in the assessment payload.",
                source="bedrock",
            )
        ]

    def _evaluate_locally(self, resource: ResourceBlock, rule: PolicyRule, resources_in_file: list[ResourceBlock]) -> Finding:
        rule_id = rule.id.upper()
        if rule_id == "SOC2-ENC-001":
            return self._check_s3_encryption(resource, rule)
        if rule_id == "SOC2-LOG-001":
            return self._check_s3_logging(resource, rule)
        if rule_id == "SOC2-NET-001":
            return self._check_s3_public_access(resource, rule, resources_in_file)
        if rule_id == "SOC2-ENC-002":
            return self._check_rds_encryption(resource, rule)
        if rule_id == "SOC2-NET-002":
            return self._check_security_group_ingress(resource, rule)

        return Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            status="WARN",
            message="No local evaluator implemented yet; wire this rule to Bedrock or add a deterministic check.",
            proof=rule.constraint,
            remediation=rule.remediation,
            source="local",
        )

    def _check_s3_encryption(self, resource: ResourceBlock, rule: PolicyRule) -> Finding:
        if resource.resource_type != "aws_s3_bucket":
            return self._not_applicable(rule, "Rule currently checks Terraform aws_s3_bucket resources only.")

        encrypted = self._has_nested_block(resource.properties, "server_side_encryption_configuration")
        status = "PASS" if encrypted else "FAIL"
        message = (
            "S3 encryption block detected."
            if encrypted
            else "No server_side_encryption_configuration block found on the bucket."
        )
        proof = yaml.safe_dump(resource.properties, sort_keys=True)
        return Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            status=status,
            message=message,
            proof=proof,
            remediation=rule.remediation,
        )

    def _check_s3_logging(self, resource: ResourceBlock, rule: PolicyRule) -> Finding:
        if resource.resource_type != "aws_s3_bucket":
            return self._not_applicable(rule, "Rule currently checks Terraform aws_s3_bucket resources only.")
        has_logging = self._has_nested_block(resource.properties, "logging")
        return Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            status="PASS" if has_logging else "FAIL",
            message="Bucket logging is configured." if has_logging else "Bucket logging block is missing.",
            proof=yaml.safe_dump(resource.properties, sort_keys=True),
            remediation=rule.remediation,
        )

    def _check_s3_public_access(self, resource: ResourceBlock, rule: PolicyRule, resources_in_file: list[ResourceBlock]) -> Finding:
        if resource.resource_type == "aws_s3_bucket_public_access_block":
            required = [
                self._bool_value(resource.properties, "block_public_acls"),
                self._bool_value(resource.properties, "block_public_policy"),
                self._bool_value(resource.properties, "ignore_public_acls"),
                self._bool_value(resource.properties, "restrict_public_buckets"),
            ]
            all_enabled = all(value is True for value in required)
            return Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                status="PASS" if all_enabled else "FAIL",
                message=(
                    "All public access block protections are enabled."
                    if all_enabled
                    else "One or more public access block flags are disabled or missing."
                ),
                proof=yaml.safe_dump(resource.properties, sort_keys=True),
                remediation=rule.remediation,
            )

        if resource.resource_type != "aws_s3_bucket":
            return self._not_applicable(rule, "Rule currently checks Terraform S3 bucket resources only.")

        acl = str(resource.properties.get("acl", "private"))
        has_pab = any(r.resource_type == "aws_s3_bucket_public_access_block" for r in resources_in_file)
        if acl in {"public-read", "public-read-write", "website"}:
            status = "FAIL"
            message = f"Bucket ACL is explicitly public: {acl}."
        elif has_pab:
            status = "PASS"
            message = "A public access block resource exists in the same file."
        else:
            status = "FAIL"
            message = "No aws_s3_bucket_public_access_block resource found in the same file."

        return Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            status=status,
            message=message,
            proof=yaml.safe_dump(resource.properties, sort_keys=True),
            remediation=rule.remediation,
        )

    def _check_rds_encryption(self, resource: ResourceBlock, rule: PolicyRule) -> Finding:
        if resource.resource_type != "aws_db_instance":
            return self._not_applicable(rule, "Rule currently checks Terraform aws_db_instance resources only.")
        encrypted = self._bool_value(resource.properties, "storage_encrypted") is True
        has_kms = bool(resource.properties.get("kms_key_id"))
        passed = encrypted and has_kms
        message = "RDS storage encryption is enabled with a KMS key." if passed else "RDS encryption or kms_key_id is missing."
        return Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            status="PASS" if passed else "FAIL",
            message=message,
            proof=yaml.safe_dump(resource.properties, sort_keys=True),
            remediation=rule.remediation,
        )

    def _check_security_group_ingress(self, resource: ResourceBlock, rule: PolicyRule) -> Finding:
        if resource.resource_type != "aws_security_group":
            return self._not_applicable(rule, "Rule currently checks Terraform aws_security_group resources only.")

        violations: list[str] = []
        for ingress in self._list_of_dicts(resource.properties.get("ingress")):
            cidrs = self._ensure_list(ingress.get("cidr_blocks")) + self._ensure_list(ingress.get("ipv6_cidr_blocks"))
            public = any(cidr in {"0.0.0.0/0", "::/0"} for cidr in cidrs)
            from_port = self._int_value(ingress.get("from_port"))
            to_port = self._int_value(ingress.get("to_port"))
            if not public or from_port is None or to_port is None:
                continue
            if from_port <= 22 <= to_port:
                violations.append("SSH is open to the internet.")
            elif from_port != 443 or to_port != 443:
                violations.append(f"Public ingress allowed on ports {from_port}-{to_port}.")

        passed = not violations
        return Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            status="PASS" if passed else "FAIL",
            message="Security group ingress is restricted." if passed else " ".join(violations),
            proof=yaml.safe_dump(resource.properties, sort_keys=True),
            remediation=rule.remediation,
        )

    def _build_normalized_resource_text(self, resource: ResourceBlock) -> str:
        lines = [
            f"Resource type: {resource.resource_type}",
            f"Resource name: {resource.resource_name}",
        ]
        if resource.line_number is not None:
            lines.append(f"Declared at line: {resource.line_number}")

        if resource.resource_type == "aws_s3_bucket":
            lines.append(
                "Server-side encryption configured: "
                f"{self._has_nested_block(resource.properties, 'server_side_encryption_configuration')}"
            )
            lines.append(f"Logging configured: {self._has_nested_block(resource.properties, 'logging')}")
            lines.append(f"ACL: {resource.properties.get('acl', 'private')}")
        elif resource.resource_type == "aws_db_instance":
            lines.append(f"Storage encrypted: {self._bool_value(resource.properties, 'storage_encrypted')}")
            lines.append(f"KMS key configured: {bool(resource.properties.get('kms_key_id'))}")
        elif resource.resource_type == "aws_security_group":
            lines.append(f"Ingress rule count: {len(self._list_of_dicts(resource.properties.get('ingress')))}")

        lines.append("Properties:")
        lines.append(yaml.safe_dump(resource.properties, sort_keys=True).strip())
        return "\n".join(lines)

    def _has_nested_block(self, properties: dict[str, Any], key: str) -> bool:
        value = properties.get(key)
        return bool(value)

    def _bool_value(self, properties: dict[str, Any], key: str) -> bool | None:
        value = properties.get(key)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.lower()
            if lowered == "true":
                return True
            if lowered == "false":
                return False
        return None

    def _list_of_dicts(self, value: Any) -> list[dict[str, Any]]:
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            return [value]
        return []

    def _ensure_list(self, value: Any) -> list[Any]:
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    def _int_value(self, value: Any) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _not_applicable(self, rule: PolicyRule, message: str) -> Finding:
        return Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            status="WARN",
            message=message,
            proof=rule.constraint,
            remediation=rule.remediation,
        )
