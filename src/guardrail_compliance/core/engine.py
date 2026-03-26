from __future__ import annotations

from pathlib import Path

from .guardrail_client import BedrockGuardrailClient
from .models import Finding, ResourceEvaluation, ScanResult
from .normalization import NormalizedResource, ResourceNormalizer
from ..parsers import CloudFormationParser, KubernetesParser, TerraformParser
from ..parsers.base import IaCParser, ResourceBlock
from ..policies.registry import PolicyDefinition, PolicyRegistry, PolicyRule
from ..utils.config import EngineConfig
from ..utils.exceptions import ParserError

# ---------------------------------------------------------------------------
# Generic keyword routing table
# ---------------------------------------------------------------------------
# Maps resource types to (keywords, checker_method) pairs for rules that don't
# have an explicit rule-ID entry in _RULE_DISPATCH.  Terraform and
# CloudFormation equivalents share the same route list.

_ROUTE_DEFINITIONS: list[tuple[list[str], list[tuple[list[str], str]]]] = [
    (
        ["aws_s3_bucket", "AWS::S3::Bucket"],
        [
            (["encrypt"], "_check_s3_encryption"),
            (["log"], "_check_s3_logging"),
            (["public", "access block"], "_check_s3_public_access"),
        ],
    ),
    (
        ["aws_s3_bucket_public_access_block", "AWS::S3::BucketPublicAccessBlock"],
        [(["public", "access block"], "_check_s3_public_access")],
    ),
    (
        ["aws_db_instance", "AWS::RDS::DBInstance"],
        [(["encrypt", "kms"], "_check_rds_encryption")],
    ),
    (
        ["aws_security_group", "AWS::EC2::SecurityGroup"],
        [(["ssh", "ingress", "public", "administrative", "admin port"], "_check_security_group_ingress")],
    ),
    (
        ["aws_iam_account_password_policy", "AWS::IAM::AccountPasswordPolicy"],
        [(["password"], "_check_password_policy")],
    ),
]

_GENERIC_ROUTES: dict[str, list[tuple[list[str], str]]] = {
    rtype: routes for rtypes, routes in _ROUTE_DEFINITIONS for rtype in rtypes
}

_PUBLIC_ACLS = {"public-read", "public-read-write", "website", "publicread", "publicreadwrite", "authenticatedread"}


class ComplianceEngine:
    """Orchestrates IaC parsing, resource normalisation, and compliance evaluation.

    For each resource the engine either delegates to AWS Bedrock Automated
    Reasoning (when a guardrail binding exists) or runs a local deterministic
    check.
    """

    # Rule-ID -> checker method name for deterministic dispatch.
    _RULE_DISPATCH: dict[str, str] = {
        "SOC2-ENC-001": "_check_s3_encryption",
        "SOC2-LOG-001": "_check_s3_logging",
        "SOC2-NET-001": "_check_s3_public_access",
        "SOC2-ENC-002": "_check_rds_encryption",
        "SOC2-NET-002": "_check_security_group_ingress",
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
        parser = self._detect_parser(file_path)
        resources = parser.parse(file_path)
        selected = self.config.selected_policies or [p.name for p in self.policy_registry.all()]
        evaluations: list[ResourceEvaluation] = []

        for resource in resources:
            normalized = self.normalizer.normalize(resource, resources)
            findings: list[Finding] = []
            grouped = self._group_rules_by_policy(
                self.policy_registry.match_rules(resource.resource_type, selected)
            )

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

        return ScanResult(file_path=file_path, parser=parser.__class__.__name__, resources=evaluations)

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
        """Run a deterministic local check for *rule* against *resource*.

        Dispatch priority: exact rule-ID match first, then keyword-based generic routing.
        """
        method_name = self._RULE_DISPATCH.get(rule.id.upper()) or self._route_generic(resource, rule)
        if method_name:
            return getattr(self, method_name)(resource, normalized, rule)
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
    def _route_generic(resource: ResourceBlock, rule: PolicyRule) -> str | None:
        """Find a checker via keyword matching when there is no exact rule-ID dispatch."""
        routes = _GENERIC_ROUTES.get(resource.resource_type)
        if not routes:
            return None
        text = f"{rule.title} {rule.description} {rule.constraint}".lower()
        for keywords, method_name in routes:
            if any(kw in text for kw in keywords):
                return method_name
        return None

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
