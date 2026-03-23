from __future__ import annotations

from collections import OrderedDict
from pathlib import Path

from .guardrail_client import BedrockGuardrailClient
from .models import Finding, ResourceEvaluation, ScanResult
from .normalization import NormalizedResource, ResourceNormalizer
from ..parsers import CloudFormationParser, KubernetesParser, TerraformParser
from ..parsers.base import IaCParser, ResourceBlock
from ..policies.registry import PolicyDefinition, PolicyRegistry, PolicyRule
from ..utils.config import EngineConfig
from ..utils.exceptions import ParserError


class ComplianceEngine:
    def __init__(self, config: EngineConfig) -> None:
        self.config = config
        project_root = Path(__file__).resolve().parents[3]
        policy_dir = config.resolve_policy_dir(project_root)
        self.policy_registry = PolicyRegistry(policy_dir)
        self.parsers: list[IaCParser] = [TerraformParser(), CloudFormationParser(), KubernetesParser()]
        self.normalizer = ResourceNormalizer()
        self._client_cache: dict[tuple[str, str], BedrockGuardrailClient] = {}

    async def scan(self, file_path: Path) -> ScanResult:
        parser = self._detect_parser(file_path)
        resources = parser.parse(file_path)
        selected = self.config.selected_policies or [policy.name for policy in self.policy_registry.all()]
        evaluations: list[ResourceEvaluation] = []

        for resource in resources:
            normalized = self.normalizer.normalize(resource, resources)
            findings: list[Finding] = []
            matched_rules = self.policy_registry.match_rules(resource.resource_type, selected)
            grouped = self._group_rules_by_policy(matched_rules)

            for policy, rules in grouped.values():
                if self.config.use_bedrock and policy.guardrail_id:
                    findings.extend(await self._evaluate_with_bedrock(resource, normalized, policy, rules))
                else:
                    for rule in rules:
                        findings.append(self._evaluate_locally(resource, normalized, rule))

            evaluations.append(
                ResourceEvaluation(
                    resource_type=resource.resource_type,
                    resource_name=resource.resource_name,
                    file_path=resource.file_path,
                    line_number=resource.line_number,
                    normalized_text=normalized.text,
                    normalized_facts=normalized.facts,
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

    def _group_rules_by_policy(
        self,
        matches: list[tuple[PolicyDefinition, PolicyRule]],
    ) -> OrderedDict[str, tuple[PolicyDefinition, list[PolicyRule]]]:
        grouped: OrderedDict[str, tuple[PolicyDefinition, list[PolicyRule]]] = OrderedDict()
        for policy, rule in matches:
            if policy.name not in grouped:
                grouped[policy.name] = (policy, [])
            grouped[policy.name][1].append(rule)
        return grouped

    async def _evaluate_with_bedrock(
        self,
        resource: ResourceBlock,
        normalized: NormalizedResource,
        policy: PolicyDefinition,
        rules: list[PolicyRule],
    ) -> list[Finding]:
        client = self._client_cache.setdefault(
            (policy.guardrail_id or "", policy.guardrail_version),
            BedrockGuardrailClient(
                guardrail_id=policy.guardrail_id or "",
                guardrail_version=policy.guardrail_version,
                region=self.config.region,
            ),
        )
        compliance = await client.evaluate(normalized.text, content_type=resource.resource_type)
        if compliance.findings:
            return compliance.findings

        expected_rules = ", ".join(rule.id for rule in rules)
        status = "PASS" if compliance.action == "NONE" else "WARN"
        return [
            Finding(
                rule_id=f"{policy.name.upper()}-NO-FINDINGS",
                title=f"{policy.name} automated reasoning result",
                severity="LOW",
                status=status,
                message=(
                    f"ApplyGuardrail returned action={compliance.action} with no explicit findings "
                    f"for rules: {expected_rules}."
                ),
                proof="No automated reasoning findings were returned in the assessment payload.",
                source="bedrock",
            )
        ]

    def _evaluate_locally(self, resource: ResourceBlock, normalized: NormalizedResource, rule: PolicyRule) -> Finding:
        rule_id = rule.id.upper()
        if rule_id == "SOC2-ENC-001":
            return self._check_s3_encryption(resource, normalized, rule)
        if rule_id == "SOC2-LOG-001":
            return self._check_s3_logging(resource, normalized, rule)
        if rule_id == "SOC2-NET-001":
            return self._check_s3_public_access(resource, normalized, rule)
        if rule_id == "SOC2-ENC-002":
            return self._check_rds_encryption(resource, normalized, rule)
        if rule_id == "SOC2-NET-002":
            return self._check_security_group_ingress(resource, normalized, rule)

        auto_routed = self._route_generic_rule(resource, normalized, rule)
        if auto_routed is not None:
            return auto_routed

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

    def _check_s3_encryption(self, resource: ResourceBlock, normalized: NormalizedResource, rule: PolicyRule) -> Finding:
        if resource.resource_type not in {"aws_s3_bucket", "AWS::S3::Bucket"}:
            return self._not_applicable(rule, "Rule currently checks S3 bucket resources only.")

        encrypted = bool(normalized.facts.get("encryption_configured"))
        return Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            status="PASS" if encrypted else "FAIL",
            message="S3 encryption block detected." if encrypted else "No server_side_encryption_configuration block found on the bucket.",
            proof=normalized.text,
            remediation=rule.remediation,
        )

    def _check_s3_logging(self, resource: ResourceBlock, normalized: NormalizedResource, rule: PolicyRule) -> Finding:
        if resource.resource_type not in {"aws_s3_bucket", "AWS::S3::Bucket"}:
            return self._not_applicable(rule, "Rule currently checks S3 bucket resources only.")

        has_logging = bool(normalized.facts.get("logging_configured"))
        return Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            status="PASS" if has_logging else "FAIL",
            message="Bucket logging is configured." if has_logging else "Bucket logging block is missing.",
            proof=normalized.text,
            remediation=rule.remediation,
        )

    def _check_s3_public_access(self, resource: ResourceBlock, normalized: NormalizedResource, rule: PolicyRule) -> Finding:
        if resource.resource_type in {"aws_s3_bucket_public_access_block", "AWS::S3::BucketPublicAccessBlock"}:
            all_enabled = bool(normalized.facts.get("all_public_access_blocks_enabled"))
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
                proof=normalized.text,
                remediation=rule.remediation,
            )

        if resource.resource_type not in {"aws_s3_bucket", "AWS::S3::Bucket"}:
            return self._not_applicable(rule, "Rule currently checks S3 bucket resources only.")

        acl = str(normalized.facts.get("acl", "private"))
        has_pab = bool(normalized.facts.get("public_access_block_present"))
        pab_all_enabled = bool(normalized.facts.get("public_access_block_all_enabled"))

        if acl.lower() in {"public-read", "public-read-write", "website", "publicread", "publicreadwrite", "authenticatedread"}:
            status = "FAIL"
            message = f"Bucket ACL is explicitly public: {acl}."
        elif has_pab and pab_all_enabled:
            status = "PASS"
            message = "A matching public access block resource exists and all protections are enabled."
        elif has_pab:
            status = "FAIL"
            message = "A matching public access block resource exists, but one or more protections are disabled."
        else:
            status = "FAIL"
            message = "No matching public access block configuration was found."

        return Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            status=status,
            message=message,
            proof=normalized.text,
            remediation=rule.remediation,
        )

    def _check_rds_encryption(self, resource: ResourceBlock, normalized: NormalizedResource, rule: PolicyRule) -> Finding:
        if resource.resource_type not in {"aws_db_instance", "AWS::RDS::DBInstance"}:
            return self._not_applicable(rule, "Rule currently checks RDS instance resources only.")

        encrypted = normalized.facts.get("storage_encrypted") is True
        has_kms = bool(normalized.facts.get("kms_key_configured"))
        passed = encrypted and has_kms
        return Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            status="PASS" if passed else "FAIL",
            message="RDS storage encryption is enabled with a KMS key." if passed else "RDS encryption or kms_key_id is missing.",
            proof=normalized.text,
            remediation=rule.remediation,
        )

    def _check_security_group_ingress(self, resource: ResourceBlock, normalized: NormalizedResource, rule: PolicyRule) -> Finding:
        if resource.resource_type not in {"aws_security_group", "AWS::EC2::SecurityGroup"}:
            return self._not_applicable(rule, "Rule currently checks security group resources only.")

        ssh_open = bool(normalized.facts.get("ssh_open_to_world"))
        public_ranges = normalized.facts.get("public_ingress_ranges") or []
        public_ports = normalized.facts.get("public_ingress_ports") or []

        if ssh_open:
            status = "FAIL"
            message = "SSH is open to the internet."
        elif public_ports and any(port != 443 for port in public_ports):
            status = "FAIL"
            message = f"Public ingress allowed on ports/ranges: {', '.join(str(port) for port in public_ports)}."
        else:
            status = "PASS"
            message = "Security group ingress is restricted."

        if public_ranges and status == "PASS":
            message = f"Security group ingress is restricted to acceptable public ranges: {', '.join(public_ranges)}."

        return Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            status=status,
            message=message,
            proof=normalized.text,
            remediation=rule.remediation,
        )

    def _route_generic_rule(
        self,
        resource: ResourceBlock,
        normalized: NormalizedResource,
        rule: PolicyRule,
    ) -> Finding | None:
        text = f"{rule.title} {rule.description} {rule.constraint}".lower()
        resource_type = resource.resource_type

        if resource_type in {"aws_s3_bucket", "AWS::S3::Bucket"}:
            if "encrypt" in text:
                return self._check_s3_encryption(resource, normalized, rule)
            if "log" in text:
                return self._check_s3_logging(resource, normalized, rule)
            if "public" in text or "access block" in text:
                return self._check_s3_public_access(resource, normalized, rule)

        if resource_type in {"aws_s3_bucket_public_access_block", "AWS::S3::BucketPublicAccessBlock"}:
            if "public" in text or "access block" in text:
                return self._check_s3_public_access(resource, normalized, rule)

        if resource_type in {"aws_db_instance", "AWS::RDS::DBInstance"}:
            if "encrypt" in text or "kms" in text:
                return self._check_rds_encryption(resource, normalized, rule)

        if resource_type in {"aws_security_group", "AWS::EC2::SecurityGroup"}:
            if any(keyword in text for keyword in ["ssh", "ingress", "public", "administrative", "admin port"]):
                return self._check_security_group_ingress(resource, normalized, rule)

        if resource_type in {"aws_iam_account_password_policy", "AWS::IAM::AccountPasswordPolicy"}:
            if "password" in text:
                return self._check_password_policy(resource, rule)

        return None

    def _check_password_policy(self, resource: ResourceBlock, rule: PolicyRule) -> Finding:
        if resource.resource_type == "AWS::IAM::AccountPasswordPolicy":
            minimum_length = self._int_value(resource.properties.get("MinimumPasswordLength"))
            require_upper = self._bool_value_value(resource.properties.get("RequireUppercaseCharacters"))
            require_lower = self._bool_value_value(resource.properties.get("RequireLowercaseCharacters"))
            require_numbers = self._bool_value_value(resource.properties.get("RequireNumbers"))
            require_symbols = self._bool_value_value(resource.properties.get("RequireSymbols"))
            reuse_prevention = self._int_value(resource.properties.get("PasswordReusePrevention"))
        else:
            minimum_length = self._int_value(resource.properties.get("minimum_password_length"))
            require_upper = self._bool_value_value(resource.properties.get("require_uppercase_characters"))
            require_lower = self._bool_value_value(resource.properties.get("require_lowercase_characters"))
            require_numbers = self._bool_value_value(resource.properties.get("require_numbers"))
            require_symbols = self._bool_value_value(resource.properties.get("require_symbols"))
            reuse_prevention = self._int_value(resource.properties.get("password_reuse_prevention"))

        passed = (
            (minimum_length or 0) >= 14
            and require_upper is True
            and require_lower is True
            and require_numbers is True
            and require_symbols is True
            and (reuse_prevention or 0) >= 24
        )
        proof = (
            f"minimum_length={minimum_length}, require_upper={require_upper}, require_lower={require_lower}, "
            f"require_numbers={require_numbers}, require_symbols={require_symbols}, reuse_prevention={reuse_prevention}"
        )
        return Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            status="PASS" if passed else "FAIL",
            message=(
                "Password policy meets strong baseline requirements."
                if passed
                else "Password policy is weaker than the configured strong baseline."
            ),
            proof=proof,
            remediation=rule.remediation,
        )

    def _int_value(self, value) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _bool_value_value(self, value) -> bool | None:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.lower()
            if lowered == "true":
                return True
            if lowered == "false":
                return False
        return None

    def _int_value(self, value: object) -> int | None:
        try:
            return int(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return None

    def _bool_value_value(self, value: object) -> bool | None:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.lower()
            if lowered == "true":
                return True
            if lowered == "false":
                return False
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
