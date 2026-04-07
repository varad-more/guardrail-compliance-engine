from __future__ import annotations

import logging
from pathlib import Path

from ..parsers import CloudFormationParser, KubernetesParser, TerraformParser
from ..parsers.base import IaCParser, ResourceBlock
from ..policies.registry import PolicyDefinition, PolicyRegistry, PolicyRule
from ..remediation.snippets import get_snippet
from ..utils.config import EngineConfig
from ..utils.exceptions import ParserError
from .guardrail_client import BedrockGuardrailClient
from .models import Finding, ResourceEvaluation, ScanResult
from .normalization import NormalizedResource, ResourceNormalizer

log = logging.getLogger(__name__)

_PUBLIC_ACLS = {"public-read", "public-read-write", "website", "publicread", "publicreadwrite", "authenticatedread"}


class ComplianceEngine:
    """Orchestrates IaC parsing, resource normalisation, and compliance evaluation.

    For each resource the engine either delegates to AWS Bedrock Automated
    Reasoning (when a guardrail binding exists) or runs a local deterministic
    check.
    """

    # Rule-ID -> checker method name for deterministic local evaluation.
    # Every rule that can be checked locally must be listed here.
    _RULE_DISPATCH: dict[str, str] = {
        "SOC2-ENC-001": "_check_s3_encryption",
        "SOC2-LOG-001": "_check_s3_logging",
        "SOC2-NET-001": "_check_s3_public_access",
        "SOC2-ENC-002": "_check_rds_encryption",
        "SOC2-NET-002": "_check_security_group_ingress",
        "CIS-S3-001": "_check_s3_encryption",
        "CIS-S3-002": "_check_s3_public_access",
        "CIS-RDS-001": "_check_rds_encryption",
        "CIS-NET-001": "_check_security_group_ingress",
        "CIS-IAM-001": "_check_password_policy",
        "PCI-ENC-001": "_check_rds_encryption",
        "PCI-NET-001": "_check_security_group_ingress",
        "PCI-LOG-001": "_check_s3_logging",
        "HIPAA-ENC-001": "_check_rds_encryption",
        "HIPAA-ENC-002": "_check_s3_public_access",
        "HIPAA-LOG-001": "_check_s3_logging",
        "HIPAA-NET-001": "_check_security_group_ingress",
        "HIPAA-BKP-001": "_check_rds_backup",
        "PCI-STO-001": "_check_s3_public_access",
        "PCI-IAM-001": "_check_password_policy",
        "CIS-CT-001": "_check_cloudtrail_logging",
        "SOC2-LOG-002": "_check_cloudtrail_logging",
        "CIS-EBS-001": "_check_ebs_encryption",
        "SOC2-ENC-003": "_check_ebs_encryption",
        "SOC2-ENC-004": "_check_dynamodb_encryption",
        "CIS-VPC-001": "_check_vpc_flow_logs",
        "K8S-SEC-001": "_check_k8s_privileged",
        "K8S-SEC-002": "_check_k8s_run_as_root",
        "K8S-SEC-003": "_check_k8s_resource_limits",
        "K8S-SEC-004": "_check_k8s_host_namespaces",
        "K8S-SEC-005": "_check_k8s_probes",
    }

    def __init__(self, config: EngineConfig) -> None:
        self.config = config
        project_root = Path(__file__).resolve().parents[3]
        policy_dir = config.resolve_policy_dir(project_root)
        self.policy_registry = PolicyRegistry(policy_dir)
        self.parsers: list[IaCParser] = [TerraformParser(), CloudFormationParser(), KubernetesParser()]
        self.normalizer = ResourceNormalizer()
        self._client_cache: dict[tuple[str, str], BedrockGuardrailClient] = {}

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    async def scan(self, file_path: Path) -> ScanResult:
        """Parse a single file and evaluate all matched policy rules."""
        log.info("Scanning %s", file_path)
        parser = self._detect_parser(file_path)
        log.debug("Using parser %s for %s", parser.__class__.__name__, file_path)
        resources = parser.parse(file_path)
        log.debug("Parsed %d resource(s) from %s", len(resources), file_path)
        selected = self.config.selected_policies or [p.name for p in self.policy_registry.all()]
        evaluations: list[ResourceEvaluation] = []

        for resource in resources:
            normalized = self.normalizer.normalize(resource, resources)
            findings: list[Finding] = []
            matched = self.policy_registry.match_rules(resource.resource_type, selected)

            # Filter out rules suppressed by inline # guardrail:ignore comments.
            if resource.suppressed_rules:
                if resource.suppress_all:
                    log.debug("All rules suppressed for %s/%s", resource.resource_type, resource.resource_name)
                    matched = []
                else:
                    matched = [(p, r) for p, r in matched if r.id not in resource.suppressed_rules]

            grouped = self._group_rules_by_policy(matched)

            for policy, rules in grouped.values():
                if self.config.use_bedrock and policy.guardrail_id:
                    findings.extend(await self._evaluate_with_bedrock(resource, normalized, policy, rules))
                else:
                    findings.extend(self._evaluate_locally(resource, normalized, rule) for rule in rules)

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

        result = ScanResult(file_path=file_path, parser=parser.__class__.__name__, resources=evaluations)
        log.info("Scan complete: %s — %d resource(s), %d finding(s)", file_path, len(result.resources), result.total_findings)
        return result

    async def scan_directory(self, dir_path: Path, recursive: bool = True) -> list[ScanResult]:
        """Scan all supported IaC files in a directory."""
        pattern = "**/*" if recursive else "*"
        supported = sorted(
            p for p in dir_path.glob(pattern)
            if p.is_file() and any(parser.supports(p) for parser in self.parsers)
        )
        return [await self.scan(p) for p in supported]

    # ------------------------------------------------------------------
    # Evaluation dispatch
    # ------------------------------------------------------------------

    async def _evaluate_with_bedrock(
        self,
        resource: ResourceBlock,
        normalized: NormalizedResource,
        policy: PolicyDefinition,
        rules: list[PolicyRule],
    ) -> list[Finding]:
        """Send normalised text to Bedrock for automated reasoning evaluation."""
        log.debug(
            "Evaluating %s/%s via Bedrock guardrail %s (policy=%s)",
            resource.resource_type, resource.resource_name, policy.guardrail_id, policy.name,
        )
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

        expected = ", ".join(r.id for r in rules)
        return [
            Finding(
                rule_id=f"{policy.name.upper()}-NO-FINDINGS",
                title=f"{policy.name} automated reasoning result",
                severity="LOW",
                status="PASS" if compliance.action == "NONE" else "WARN",
                message=f"ApplyGuardrail returned action={compliance.action} with no findings for: {expected}.",
                proof="No automated reasoning findings were returned in the assessment payload.",
                source="bedrock",
            )
        ]

    def _evaluate_locally(self, resource: ResourceBlock, normalized: NormalizedResource, rule: PolicyRule) -> Finding:
        """Run a deterministic local check for *rule* against *resource*."""
        method_name = self._RULE_DISPATCH.get(rule.id.upper())
        if method_name:
            finding = getattr(self, method_name)(resource, normalized, rule)
            if finding.status == "FAIL":
                finding.remediation_snippet = get_snippet(method_name, resource.resource_type)
            return finding
        return self._finding(rule, status="WARN",
                             message="No local evaluator yet; wire this rule to Bedrock or add a check.",
                             proof=rule.constraint, source="local")

    # ------------------------------------------------------------------
    # Deterministic checkers
    # ------------------------------------------------------------------

    def _check_s3_encryption(self, resource: ResourceBlock, normalized: NormalizedResource, rule: PolicyRule) -> Finding:
        """Check whether the S3 bucket has server-side encryption configured."""
        if resource.resource_type not in {"aws_s3_bucket", "AWS::S3::Bucket"}:
            return self._not_applicable(rule)
        encrypted = bool(normalized.facts.get("encryption_configured"))
        return self._finding(
            rule, status="PASS" if encrypted else "FAIL",
            message="S3 encryption block detected." if encrypted else "No encryption configuration found.",
            proof=normalized.text,
        )

    def _check_s3_logging(self, resource: ResourceBlock, normalized: NormalizedResource, rule: PolicyRule) -> Finding:
        """Check whether S3 bucket logging is enabled."""
        if resource.resource_type not in {"aws_s3_bucket", "AWS::S3::Bucket"}:
            return self._not_applicable(rule)
        has_logging = bool(normalized.facts.get("logging_configured"))
        return self._finding(
            rule, status="PASS" if has_logging else "FAIL",
            message="Bucket logging is configured." if has_logging else "Bucket logging is missing.",
            proof=normalized.text,
        )

    def _check_s3_public_access(self, resource: ResourceBlock, normalized: NormalizedResource, rule: PolicyRule) -> Finding:
        """Check S3 public access — works for both bucket and public-access-block resources."""
        if resource.resource_type in {"aws_s3_bucket_public_access_block", "AWS::S3::BucketPublicAccessBlock"}:
            ok = bool(normalized.facts.get("all_public_access_blocks_enabled"))
            return self._finding(
                rule, status="PASS" if ok else "FAIL",
                message="All public access block protections are enabled." if ok
                else "One or more public access block flags are disabled or missing.",
                proof=normalized.text,
            )

        if resource.resource_type not in {"aws_s3_bucket", "AWS::S3::Bucket"}:
            return self._not_applicable(rule)

        acl = str(normalized.facts.get("acl", "private")).lower()
        has_pab = bool(normalized.facts.get("public_access_block_present"))
        pab_ok = bool(normalized.facts.get("public_access_block_all_enabled"))

        if acl in _PUBLIC_ACLS:
            status, message = "FAIL", f"Bucket ACL is explicitly public: {acl}."
        elif has_pab and pab_ok:
            status, message = "PASS", "Public access block exists with all protections enabled."
        elif has_pab:
            status, message = "FAIL", "Public access block exists but one or more protections are disabled."
        else:
            status, message = "FAIL", "No public access block configuration found."

        return self._finding(rule, status=status, message=message, proof=normalized.text)

    def _check_rds_encryption(self, resource: ResourceBlock, normalized: NormalizedResource, rule: PolicyRule) -> Finding:
        """Check RDS storage encryption with a KMS key."""
        if resource.resource_type not in {"aws_db_instance", "AWS::RDS::DBInstance"}:
            return self._not_applicable(rule)
        ok = normalized.facts.get("storage_encrypted") is True and bool(normalized.facts.get("kms_key_configured"))
        return self._finding(
            rule, status="PASS" if ok else "FAIL",
            message="RDS encryption enabled with KMS key." if ok else "RDS encryption or kms_key_id is missing.",
            proof=normalized.text,
        )

    def _check_rds_backup(self, resource: ResourceBlock, normalized: NormalizedResource, rule: PolicyRule) -> Finding:
        """Check that RDS automated backups are configured with a positive retention period."""
        retention = normalized.facts.get("backup_retention_period")
        ok = retention is not None and retention > 0
        return self._finding(
            rule, status="PASS" if ok else "FAIL",
            message=f"RDS backup retention is {retention} day(s)." if ok else "RDS backup retention is not configured.",
            proof=normalized.text,
        )

    def _check_security_group_ingress(self, resource: ResourceBlock, normalized: NormalizedResource, rule: PolicyRule) -> Finding:
        """Check that security group ingress rules restrict SSH and other admin ports."""
        if resource.resource_type not in {"aws_security_group", "AWS::EC2::SecurityGroup"}:
            return self._not_applicable(rule)

        ssh_open = bool(normalized.facts.get("ssh_open_to_world"))
        public_ports = normalized.facts.get("public_ingress_ports") or []
        public_ranges = normalized.facts.get("public_ingress_ranges") or []

        if ssh_open:
            status, message = "FAIL", "SSH is open to the internet."
        elif public_ports and any(port != 443 for port in public_ports):
            status, message = "FAIL", f"Public ingress on ports: {', '.join(str(p) for p in public_ports)}."
        elif public_ranges:
            status, message = "PASS", f"Ingress restricted to acceptable ranges: {', '.join(public_ranges)}."
        else:
            status, message = "PASS", "Security group ingress is restricted."

        return self._finding(rule, status=status, message=message, proof=normalized.text)

    def _check_password_policy(self, resource: ResourceBlock, normalized: NormalizedResource, rule: PolicyRule) -> Finding:
        """Verify IAM password policy meets the strong baseline (length >= 14, complexity, reuse >= 24)."""
        facts = normalized.facts
        passed = (
            (facts.get("minimum_length") or 0) >= 14
            and facts.get("require_upper") is True
            and facts.get("require_lower") is True
            and facts.get("require_numbers") is True
            and facts.get("require_symbols") is True
            and (facts.get("reuse_prevention") or 0) >= 24
        )
        proof = ", ".join(f"{k}={facts.get(k)}" for k in (
            "minimum_length", "require_upper", "require_lower",
            "require_numbers", "require_symbols", "reuse_prevention",
        ))
        return self._finding(
            rule, status="PASS" if passed else "FAIL",
            message="Password policy meets strong baseline." if passed
            else "Password policy is weaker than the configured baseline.",
            proof=proof,
        )

    # ------------------------------------------------------------------
    # AWS extended checkers
    # ------------------------------------------------------------------

    def _check_cloudtrail_logging(self, resource: ResourceBlock, normalized: NormalizedResource, rule: PolicyRule) -> Finding:
        facts = normalized.facts
        ok = facts.get("is_logging") and facts.get("is_multi_region") and facts.get("log_file_validation")
        if ok:
            return self._finding(rule, status="PASS", message="CloudTrail is enabled with multi-region and log file validation.", proof=normalized.text)
        problems = []
        if not facts.get("is_logging"):
            problems.append("logging disabled")
        if not facts.get("is_multi_region"):
            problems.append("not multi-region")
        if not facts.get("log_file_validation"):
            problems.append("log file validation disabled")
        return self._finding(rule, status="FAIL", message=f"CloudTrail issues: {', '.join(problems)}.", proof=normalized.text)

    def _check_ebs_encryption(self, resource: ResourceBlock, normalized: NormalizedResource, rule: PolicyRule) -> Finding:
        if normalized.facts.get("encrypted"):
            return self._finding(rule, status="PASS", message="EBS volume encryption is enabled.", proof=normalized.text)
        return self._finding(rule, status="FAIL", message="EBS volume is not encrypted.", proof=normalized.text)

    def _check_dynamodb_encryption(self, resource: ResourceBlock, normalized: NormalizedResource, rule: PolicyRule) -> Finding:
        if normalized.facts.get("sse_enabled"):
            return self._finding(rule, status="PASS", message="DynamoDB SSE is enabled.", proof=normalized.text)
        return self._finding(rule, status="FAIL", message="DynamoDB server-side encryption is not enabled.", proof=normalized.text)

    def _check_vpc_flow_logs(self, resource: ResourceBlock, normalized: NormalizedResource, rule: PolicyRule) -> Finding:
        if normalized.facts.get("log_destination"):
            return self._finding(rule, status="PASS", message="VPC flow log destination is configured.", proof=normalized.text)
        return self._finding(rule, status="FAIL", message="VPC flow log has no log destination configured.", proof=normalized.text)

    # ------------------------------------------------------------------
    # Kubernetes checkers
    # ------------------------------------------------------------------

    _K8S_TYPES = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job"}

    def _check_k8s_privileged(self, resource: ResourceBlock, normalized: NormalizedResource, rule: PolicyRule) -> Finding:
        if resource.resource_type not in self._K8S_TYPES:
            return self._not_applicable(rule)
        if normalized.facts.get("privileged") is True:
            return self._finding(rule, status="FAIL", message="Container is running in privileged mode.", proof=normalized.text)
        return self._finding(rule, status="PASS", message="No containers are running in privileged mode.", proof=normalized.text)

    def _check_k8s_run_as_root(self, resource: ResourceBlock, normalized: NormalizedResource, rule: PolicyRule) -> Finding:
        if resource.resource_type not in self._K8S_TYPES:
            return self._not_applicable(rule)
        if normalized.facts.get("run_as_non_root") is True:
            return self._finding(rule, status="PASS", message="runAsNonRoot is enforced.", proof=normalized.text)
        return self._finding(rule, status="FAIL", message="runAsNonRoot is not set; containers may run as root.", proof=normalized.text)

    def _check_k8s_resource_limits(self, resource: ResourceBlock, normalized: NormalizedResource, rule: PolicyRule) -> Finding:
        if resource.resource_type not in self._K8S_TYPES:
            return self._not_applicable(rule)
        if normalized.facts.get("all_containers_have_resource_limits"):
            return self._finding(rule, status="PASS", message="All containers have resource limits.", proof=normalized.text)
        missing = normalized.facts.get("containers_missing_limits") or []
        return self._finding(rule, status="FAIL",
                             message=f"Containers missing resource limits: {', '.join(missing) or 'unknown'}.",
                             proof=normalized.text)

    def _check_k8s_host_namespaces(self, resource: ResourceBlock, normalized: NormalizedResource, rule: PolicyRule) -> Finding:
        if resource.resource_type not in self._K8S_TYPES:
            return self._not_applicable(rule)
        violations = [ns for ns in ("host_network", "host_pid", "host_ipc") if normalized.facts.get(ns)]
        if violations:
            return self._finding(rule, status="FAIL",
                                 message=f"Pod uses host namespaces: {', '.join(violations)}.",
                                 proof=normalized.text)
        return self._finding(rule, status="PASS", message="No host namespace sharing.", proof=normalized.text)

    def _check_k8s_probes(self, resource: ResourceBlock, normalized: NormalizedResource, rule: PolicyRule) -> Finding:
        if resource.resource_type not in self._K8S_TYPES:
            return self._not_applicable(rule)
        if normalized.facts.get("all_containers_have_probes"):
            return self._finding(rule, status="PASS", message="All containers have health probes.", proof=normalized.text)
        missing = normalized.facts.get("containers_missing_probes") or []
        return self._finding(rule, status="FAIL",
                             message=f"Containers missing probes: {', '.join(missing) or 'unknown'}.",
                             proof=normalized.text)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _detect_parser(self, file_path: Path) -> IaCParser:
        """Return the first parser that supports the given file."""
        for parser in self.parsers:
            if parser.supports(file_path):
                return parser
        raise ParserError(f"No parser available for file: {file_path}")

    def _group_rules_by_policy(
        self,
        matches: list[tuple[PolicyDefinition, PolicyRule]],
    ) -> dict[str, tuple[PolicyDefinition, list[PolicyRule]]]:
        """Group matched rules by their parent policy name."""
        grouped: dict[str, tuple[PolicyDefinition, list[PolicyRule]]] = {}
        for policy, rule in matches:
            if policy.name not in grouped:
                grouped[policy.name] = (policy, [])
            grouped[policy.name][1].append(rule)
        return grouped

    @staticmethod
    def _finding(rule: PolicyRule, *, status: str, message: str, proof: str, source: str = "local") -> Finding:
        """Shorthand to build a Finding pre-filled from the rule metadata."""
        return Finding(
            rule_id=rule.id, title=rule.title, severity=rule.severity,
            status=status, message=message, proof=proof,
            remediation=rule.remediation, source=source,
        )

    def _not_applicable(self, rule: PolicyRule) -> Finding:
        """Return a WARN finding when a checker is invoked for an unsupported resource type."""
        return self._finding(rule, status="WARN", message="Rule does not apply to this resource type.", proof=rule.constraint)
