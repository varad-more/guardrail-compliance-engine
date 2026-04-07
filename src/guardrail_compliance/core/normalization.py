from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import yaml

from ..parsers.base import ResourceBlock
from ..utils.secrets import redact_secrets

log = logging.getLogger(__name__)


@dataclass(slots=True)
class NormalizedResource:
    """Structured representation of a resource with extracted facts and a text narrative."""

    resource_type: str
    resource_name: str
    facts: dict[str, Any] = field(default_factory=dict)
    text: str = ""


# Public access block flag names in both Terraform and CloudFormation conventions.
_PAB_FLAGS_TF = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
_PAB_FLAGS_CFN = ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets")


class ResourceNormalizer:
    """Extracts deterministic facts from a parsed resource and builds a
    Bedrock-friendly plain-text narrative.

    Terraform uses snake_case property keys while CloudFormation uses PascalCase.
    The ``_prop`` helper picks the right key automatically so each fact-builder
    method only needs to be written once.
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def normalize(self, resource: ResourceBlock, resources_in_file: list[ResourceBlock]) -> NormalizedResource:
        """Build a NormalizedResource with structured facts and narrative text."""
        facts = self._build_facts(resource, resources_in_file)
        return NormalizedResource(
            resource_type=resource.resource_type,
            resource_name=resource.resource_name,
            facts=facts,
            text=self._facts_to_text(resource, facts),
        )

    # ------------------------------------------------------------------
    # Property access helpers
    # ------------------------------------------------------------------

    def _prop(self, resource: ResourceBlock, tf_key: str, cfn_key: str, default: Any = None) -> Any:
        """Get a property using the correct key convention for the resource type."""
        key = cfn_key if self._is_cfn(resource) else tf_key
        return resource.properties.get(key, default)

    def _dict_prop(self, d: dict[str, Any], tf_key: str, cfn_key: str, *, is_cfn: bool) -> Any:
        """Like ``_prop`` but operates on an arbitrary dict (e.g. an ingress rule)."""
        return d.get(cfn_key if is_cfn else tf_key)

    @staticmethod
    def _is_cfn(resource: ResourceBlock) -> bool:
        """Return True if the resource uses CloudFormation naming conventions."""
        return resource.resource_type.startswith("AWS::")

    # ------------------------------------------------------------------
    # Fact dispatching
    # ------------------------------------------------------------------

    # Maps resource types to fact-builder method names.  Methods that accept
    # ``resources_in_file`` are marked with True; the rest only take the
    # single resource.
    _FACT_BUILDERS: dict[str, tuple[str, bool]] = {
        rt: entry
        for rtypes, entry in [
            (("aws_s3_bucket", "AWS::S3::Bucket"), ("_s3_bucket_facts", True)),
            (("aws_s3_bucket_public_access_block", "AWS::S3::BucketPublicAccessBlock"), ("_s3_public_access_block_facts", False)),
            (("aws_db_instance", "AWS::RDS::DBInstance"), ("_rds_instance_facts", False)),
            (("aws_security_group", "AWS::EC2::SecurityGroup"), ("_security_group_facts", False)),
            (("aws_iam_account_password_policy", "AWS::IAM::AccountPasswordPolicy"), ("_password_policy_facts", False)),
            (("Pod", "Deployment", "StatefulSet", "DaemonSet", "Job"), ("_kubernetes_workload_facts", False)),
            (("aws_cloudtrail", "AWS::CloudTrail::Trail"), ("_cloudtrail_facts", False)),
            (("aws_ebs_volume", "AWS::EC2::Volume"), ("_ebs_volume_facts", False)),
            (("aws_dynamodb_table", "AWS::DynamoDB::Table"), ("_dynamodb_table_facts", False)),
            (("aws_flow_log", "AWS::EC2::FlowLog"), ("_flow_log_facts", False)),
        ]
        for rt in rtypes
    }

    def _build_facts(self, resource: ResourceBlock, resources_in_file: list[ResourceBlock]) -> dict[str, Any]:
        """Dispatch to the correct fact-builder based on resource type."""
        facts: dict[str, Any] = {
            "resource_type": resource.resource_type,
            "resource_name": resource.resource_name,
            "line_number": resource.line_number,
        }

        entry = self._FACT_BUILDERS.get(resource.resource_type)
        if entry:
            method_name, needs_siblings = entry
            method = getattr(self, method_name)
            facts.update(method(resource, resources_in_file) if needs_siblings else method(resource))
        else:
            facts["properties"] = resource.properties

        return facts

    # ------------------------------------------------------------------
    # Per-resource-type fact builders
    # ------------------------------------------------------------------

    def _s3_bucket_facts(self, resource: ResourceBlock, resources_in_file: list[ResourceBlock]) -> dict[str, Any]:
        """Extract S3 bucket encryption, logging, ACL, and public access facts."""
        is_cfn = self._is_cfn(resource)
        bucket_name = self._prop(resource, "bucket", "BucketName")
        acl = self._prop(resource, "acl", "AccessControl", "Private" if is_cfn else "private")
        encryption_block = self._prop(resource, "server_side_encryption_configuration", "BucketEncryption")
        logging_block = self._prop(resource, "logging", "LoggingConfiguration")

        if is_cfn:
            public_access_config = resource.properties.get("PublicAccessBlockConfiguration")
            matched_pabs: list[ResourceBlock] = []
            public_access_present = bool(public_access_config)
            public_access_all_enabled = self._check_public_access_flags(public_access_config)
        else:
            pab_types = {"aws_s3_bucket_public_access_block", "AWS::S3::BucketPublicAccessBlock"}
            pab_resources = [r for r in resources_in_file if r.resource_type in pab_types]
            matched_pabs = [r for r in pab_resources if self._matches_s3_bucket(r, resource)]
            public_access_present = bool(matched_pabs)
            public_access_all_enabled = any(
                self._check_public_access_flags(r.properties, is_cfn=False) for r in matched_pabs
            )

        return {
            "bucket_name": bucket_name,
            "acl": acl,
            "encryption_configured": bool(encryption_block),
            "logging_configured": bool(logging_block),
            "logging_target_bucket": self._extract_logging_target(logging_block),
            "public_access_block_present": public_access_present,
            "public_access_block_resources": [r.resource_name for r in matched_pabs],
            "public_access_block_all_enabled": public_access_all_enabled,
            "properties": resource.properties,
        }

    def _s3_public_access_block_facts(self, resource: ResourceBlock) -> dict[str, Any]:
        """Extract the four public-access-block boolean flags."""
        bucket_ref = self._prop(resource, "bucket", "Bucket")
        flags = {
            name: self._bool_value(self._prop(resource, tf, cfn))
            for name, tf, cfn in zip(
                ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"),
                _PAB_FLAGS_TF,
                _PAB_FLAGS_CFN,
                strict=True,
            )
        }
        return {
            "bucket_reference": bucket_ref,
            **flags,
            "all_public_access_blocks_enabled": all(v is True for v in flags.values()),
            "properties": resource.properties,
        }

    def _rds_instance_facts(self, resource: ResourceBlock) -> dict[str, Any]:
        """Extract RDS encryption, engine, backup, and accessibility facts."""
        return {
            "engine": self._prop(resource, "engine", "Engine"),
            "instance_class": self._prop(resource, "instance_class", "DBInstanceClass"),
            "storage_encrypted": self._bool_value(self._prop(resource, "storage_encrypted", "StorageEncrypted")),
            "kms_key_configured": bool(self._prop(resource, "kms_key_id", "KmsKeyId")),
            "backup_retention_period": self._int_value(self._prop(resource, "backup_retention_period", "BackupRetentionPeriod")),
            "publicly_accessible": self._bool_value(self._prop(resource, "publicly_accessible", "PubliclyAccessible")),
            "properties": resource.properties,
        }

    def _security_group_facts(self, resource: ResourceBlock) -> dict[str, Any]:
        """Analyse ingress rules to detect open SSH, public CIDRs, and port exposure."""
        is_cfn = self._is_cfn(resource)
        ingress_rules = self._list_of_dicts(self._prop(resource, "ingress", "SecurityGroupIngress"))
        public_ports: list[int | str] = []
        public_ranges: list[str] = []
        ssh_open = False

        for rule in ingress_rules:
            cidrs = (
                self._ensure_list(self._dict_prop(rule, "cidr_blocks", "CidrIp", is_cfn=is_cfn))
                + self._ensure_list(self._dict_prop(rule, "ipv6_cidr_blocks", "CidrIpv6", is_cfn=is_cfn))
            )
            from_port = self._int_value(self._dict_prop(rule, "from_port", "FromPort", is_cfn=is_cfn))
            to_port = self._int_value(self._dict_prop(rule, "to_port", "ToPort", is_cfn=is_cfn))

            if not any(cidr in {"0.0.0.0/0", "::/0"} for cidr in cidrs):
                continue
            if from_port is None or to_port is None:
                public_ranges.append("unknown")
                continue
            public_ranges.append(f"{from_port}-{to_port}")
            public_ports.append(from_port if from_port == to_port else f"{from_port}-{to_port}")
            if from_port <= 22 <= to_port:
                ssh_open = True

        return {
            "ingress_rule_count": len(ingress_rules),
            "public_ingress_ports": public_ports,
            "public_ingress_ranges": public_ranges,
            "ssh_open_to_world": ssh_open,
            "properties": resource.properties,
        }

    def _password_policy_facts(self, resource: ResourceBlock) -> dict[str, Any]:
        """Extract IAM password-policy strength parameters."""
        return {
            "minimum_length": self._int_value(self._prop(resource, "minimum_password_length", "MinimumPasswordLength")),
            "require_upper": self._bool_value(self._prop(resource, "require_uppercase_characters", "RequireUppercaseCharacters")),
            "require_lower": self._bool_value(self._prop(resource, "require_lowercase_characters", "RequireLowercaseCharacters")),
            "require_numbers": self._bool_value(self._prop(resource, "require_numbers", "RequireNumbers")),
            "require_symbols": self._bool_value(self._prop(resource, "require_symbols", "RequireSymbols")),
            "reuse_prevention": self._int_value(self._prop(resource, "password_reuse_prevention", "PasswordReusePrevention")),
            "properties": resource.properties,
        }

    def _cloudtrail_facts(self, resource: ResourceBlock) -> dict[str, Any]:
        """Extract CloudTrail logging configuration facts."""
        return {
            "is_logging": self._bool_value(self._prop(resource, "enable_logging", "IsLogging")) is not False,
            "is_multi_region": self._bool_value(self._prop(resource, "is_multi_region_trail", "IsMultiRegionTrail")) is True,
            "log_file_validation": self._bool_value(self._prop(resource, "enable_log_file_validation", "EnableLogFileValidation")) is True,
            "s3_bucket_name": self._prop(resource, "s3_bucket_name", "S3BucketName"),
            "properties": resource.properties,
        }

    def _ebs_volume_facts(self, resource: ResourceBlock) -> dict[str, Any]:
        """Extract EBS volume encryption facts."""
        return {
            "encrypted": self._bool_value(self._prop(resource, "encrypted", "Encrypted")) is True,
            "kms_key_configured": bool(self._prop(resource, "kms_key_id", "KmsKeyId")),
            "volume_type": self._prop(resource, "type", "VolumeType"),
            "properties": resource.properties,
        }

    def _dynamodb_table_facts(self, resource: ResourceBlock) -> dict[str, Any]:
        """Extract DynamoDB table encryption facts."""
        is_cfn = self._is_cfn(resource)
        sse = self._prop(resource, "server_side_encryption", "SSESpecification") or {}
        # Terraform heuristic parser wraps nested blocks in a list.
        if isinstance(sse, list):
            sse = sse[0] if sse else {}
        sse_dict = sse if isinstance(sse, dict) else {}
        enabled_key = "SSEEnabled" if is_cfn else "enabled"
        kms_key = "KMSMasterKeyId" if is_cfn else "kms_key_arn"
        return {
            "sse_enabled": self._bool_value(sse_dict.get(enabled_key)) is True,
            "kms_key_configured": bool(sse_dict.get(kms_key)),
            "properties": resource.properties,
        }

    def _flow_log_facts(self, resource: ResourceBlock) -> dict[str, Any]:
        """Extract VPC flow log configuration facts."""
        return {
            "traffic_type": self._prop(resource, "traffic_type", "TrafficType"),
            "log_destination": (
                self._prop(resource, "log_destination", "LogDestination")
                or self._prop(resource, "log_group_name", "LogGroupName")
            ),
            "vpc_id": self._prop(resource, "vpc_id", "ResourceId"),
            "properties": resource.properties,
        }

    def _kubernetes_workload_facts(self, resource: ResourceBlock) -> dict[str, Any]:
        """Extract container count, privilege escalation, host namespaces, limits, and probe facts."""
        spec = self._safe_dict(resource.properties, "spec")
        template_spec = self._safe_dict(self._safe_dict(spec, "template"), "spec")
        pod_spec = template_spec or spec
        containers = pod_spec.get("containers", []) if isinstance(pod_spec.get("containers"), list) else []
        return {
            "container_count": len(containers),
            "run_as_non_root": self._extract_security_value(pod_spec, containers, "runAsNonRoot"),
            "privileged": self._extract_any_container_security_value(containers, "privileged"),
            "service_account_name": pod_spec.get("serviceAccountName"),
            "host_network": bool(pod_spec.get("hostNetwork")),
            "host_pid": bool(pod_spec.get("hostPID")),
            "host_ipc": bool(pod_spec.get("hostIPC")),
            "all_containers_have_resource_limits": self._all_have_resource_limits(containers),
            "containers_missing_limits": self._containers_missing_field(containers, "resources", "limits"),
            "all_containers_have_probes": self._all_have_probes(containers),
            "containers_missing_probes": self._containers_missing_probes(containers),
            "properties": resource.properties,
        }

    # ------------------------------------------------------------------
    # Narrative text builder
    # ------------------------------------------------------------------

    def _facts_to_text(self, resource: ResourceBlock, facts: dict[str, Any]) -> str:
        """Render facts as a Bedrock-friendly plain-text narrative."""
        lines = [
            f"Resource type: {resource.resource_type}",
            f"Resource name: {resource.resource_name}",
        ]
        if resource.line_number is not None:
            lines.append(f"Declared at line: {resource.line_number}")

        skip = {"properties", "resource_type", "resource_name", "line_number"}
        for key, value in facts.items():
            if key not in skip:
                lines.append(f"{key.replace('_', ' ').capitalize()}: {value}")

        lines.append("Properties:")
        lines.append(yaml.safe_dump(resource.properties, sort_keys=True).strip())
        raw_text = "\n".join(lines)
        redacted, detected = redact_secrets(raw_text)
        if detected:
            log.warning(
                "Redacted potential secret(s) from %s/%s before sending to Bedrock: %s",
                resource.resource_type, resource.resource_name, ", ".join(detected),
            )
        return redacted

    # ------------------------------------------------------------------
    # S3 helpers
    # ------------------------------------------------------------------

    def _matches_s3_bucket(self, pab_resource: ResourceBlock, bucket_resource: ResourceBlock) -> bool:
        """Check whether a public-access-block resource is associated with a given bucket."""
        bucket_ref = str(pab_resource.properties.get("bucket", "")).strip()
        bucket_name = str(bucket_resource.properties.get("bucket", "")).strip()

        if not bucket_ref:
            return pab_resource.resource_name == bucket_resource.resource_name
        return (
            bucket_ref == bucket_name
            or (bool(bucket_resource.resource_name) and bucket_resource.resource_name in bucket_ref)
            or (bool(bucket_name) and bucket_name in bucket_ref)
        )

    def _extract_logging_target(self, logging_block: Any) -> Any:
        """Pull the target bucket from a logging configuration block."""
        blocks = self._list_of_dicts(logging_block)
        return blocks[0].get("target_bucket") if blocks else None

    def _check_public_access_flags(self, config: Any, *, is_cfn: bool = True) -> bool:
        """Return True only if all four public-access-block flags are explicitly True."""
        if not isinstance(config, dict):
            return False
        keys = _PAB_FLAGS_CFN if is_cfn else _PAB_FLAGS_TF
        return all(self._bool_value(config.get(k)) is True for k in keys)

    # ------------------------------------------------------------------
    # Kubernetes helpers
    # ------------------------------------------------------------------

    def _extract_security_value(self, pod_spec: dict[str, Any], containers: list[dict[str, Any]], key: str) -> Any:
        """Look up a securityContext field, checking pod-level first then each container."""
        pod_security = self._safe_dict(pod_spec, "securityContext")
        if key in pod_security:
            return pod_security[key]
        return self._extract_any_container_security_value(containers, key)

    def _extract_any_container_security_value(self, containers: list[dict[str, Any]], key: str) -> Any:
        """Return the first container-level securityContext value matching *key*."""
        for container in containers:
            security = self._safe_dict(container, "securityContext")
            if key in security:
                return security[key]
        return None

    @staticmethod
    def _all_have_resource_limits(containers: list[dict[str, Any]]) -> bool:
        """True only if every container has resources.limits.cpu AND resources.limits.memory."""
        if not containers:
            return False
        for c in containers:
            limits = (c.get("resources") or {}).get("limits") or {}
            if not limits.get("cpu") or not limits.get("memory"):
                return False
        return True

    @staticmethod
    def _containers_missing_field(containers: list[dict[str, Any]], parent_key: str, child_key: str) -> list[str]:
        """Return names of containers missing a nested field."""
        missing: list[str] = []
        for c in containers:
            parent = c.get(parent_key) or {}
            if not parent.get(child_key):
                missing.append(c.get("name", "unnamed"))
        return missing

    @staticmethod
    def _all_have_probes(containers: list[dict[str, Any]]) -> bool:
        """True only if every container has both livenessProbe and readinessProbe."""
        if not containers:
            return False
        return all(c.get("livenessProbe") and c.get("readinessProbe") for c in containers)

    @staticmethod
    def _containers_missing_probes(containers: list[dict[str, Any]]) -> list[str]:
        """Return names of containers missing liveness or readiness probes."""
        return [
            c.get("name", "unnamed") for c in containers
            if not c.get("livenessProbe") or not c.get("readinessProbe")
        ]

    # ------------------------------------------------------------------
    # Type coercion utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_dict(parent: dict[str, Any], key: str) -> dict[str, Any]:
        """Get a nested dict, returning ``{}`` if the value is not a dict."""
        value = parent.get(key)
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _bool_value(value: Any) -> bool | None:
        """Coerce a value to bool, returning None if it cannot be interpreted."""
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return {"true": True, "false": False}.get(value.lower())
        return None

    @staticmethod
    def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
        """Normalise a value into a list of dicts (handles single dict or list)."""
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            return [value]
        return []

    @staticmethod
    def _ensure_list(value: Any) -> list[Any]:
        """Wrap a scalar in a list; pass through lists unchanged; treat None as empty."""
        if value is None:
            return []
        return value if isinstance(value, list) else [value]

    @staticmethod
    def _int_value(value: Any) -> int | None:
        """Coerce a value to int, returning None on failure."""
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
