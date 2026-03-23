from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml

from ..parsers.base import ResourceBlock


@dataclass(slots=True)
class NormalizedResource:
    resource_type: str
    resource_name: str
    facts: dict[str, Any] = field(default_factory=dict)
    text: str = ""


class ResourceNormalizer:
    """Build deterministic facts plus a Bedrock-friendly narrative for a resource."""

    def normalize(self, resource: ResourceBlock, resources_in_file: list[ResourceBlock]) -> NormalizedResource:
        facts = self._build_facts(resource, resources_in_file)
        return NormalizedResource(
            resource_type=resource.resource_type,
            resource_name=resource.resource_name,
            facts=facts,
            text=self._facts_to_text(resource, facts),
        )

    def _build_facts(self, resource: ResourceBlock, resources_in_file: list[ResourceBlock]) -> dict[str, Any]:
        facts: dict[str, Any] = {
            "resource_type": resource.resource_type,
            "resource_name": resource.resource_name,
            "line_number": resource.line_number,
        }

        if resource.resource_type in {"aws_s3_bucket", "AWS::S3::Bucket"}:
            facts.update(self._s3_bucket_facts(resource, resources_in_file))
        elif resource.resource_type in {"aws_s3_bucket_public_access_block", "AWS::S3::BucketPublicAccessBlock"}:
            facts.update(self._s3_public_access_block_facts(resource))
        elif resource.resource_type in {"aws_db_instance", "AWS::RDS::DBInstance"}:
            facts.update(self._rds_instance_facts(resource))
        elif resource.resource_type in {"aws_security_group", "AWS::EC2::SecurityGroup"}:
            facts.update(self._security_group_facts(resource))
        elif resource.resource_type in {"Pod", "Deployment"}:
            facts.update(self._kubernetes_workload_facts(resource))
        else:
            facts["properties"] = resource.properties

        return facts

    def _s3_bucket_facts(self, resource: ResourceBlock, resources_in_file: list[ResourceBlock]) -> dict[str, Any]:
        if resource.resource_type == "AWS::S3::Bucket":
            bucket_name = resource.properties.get("BucketName")
            acl = resource.properties.get("AccessControl", "Private")
            encryption_block = resource.properties.get("BucketEncryption")
            logging_block = resource.properties.get("LoggingConfiguration")
            public_access_config = resource.properties.get("PublicAccessBlockConfiguration")
            matched_pabs: list[ResourceBlock] = []
            public_access_present = bool(public_access_config)
            public_access_all_enabled = self._cloudformation_public_access_enabled(public_access_config)
        else:
            bucket_name = resource.properties.get("bucket")
            acl = resource.properties.get("acl", "private")
            pab_resources = [
                item for item in resources_in_file if item.resource_type in {"aws_s3_bucket_public_access_block", "AWS::S3::BucketPublicAccessBlock"}
            ]
            matched_pabs = [item for item in pab_resources if self._matches_s3_bucket(item, resource)]
            encryption_block = resource.properties.get("server_side_encryption_configuration")
            logging_block = resource.properties.get("logging")
            public_access_present = bool(matched_pabs)
            public_access_all_enabled = any(self._all_public_access_flags_enabled(item) for item in matched_pabs)

        return {
            "bucket_name": bucket_name,
            "acl": acl,
            "encryption_configured": bool(encryption_block),
            "logging_configured": bool(logging_block),
            "logging_target_bucket": self._extract_logging_target_bucket(logging_block),
            "public_access_block_present": public_access_present,
            "public_access_block_resources": [item.resource_name for item in matched_pabs],
            "public_access_block_all_enabled": public_access_all_enabled,
            "properties": resource.properties,
        }

    def _s3_public_access_block_facts(self, resource: ResourceBlock) -> dict[str, Any]:
        if resource.resource_type == "AWS::S3::BucketPublicAccessBlock":
            bucket_ref = resource.properties.get("Bucket")
            block_public_acls = self._bool_value(resource.properties.get("BlockPublicAcls"))
            block_public_policy = self._bool_value(resource.properties.get("BlockPublicPolicy"))
            ignore_public_acls = self._bool_value(resource.properties.get("IgnorePublicAcls"))
            restrict_public_buckets = self._bool_value(resource.properties.get("RestrictPublicBuckets"))
        else:
            bucket_ref = resource.properties.get("bucket")
            block_public_acls = self._bool_value(resource.properties.get("block_public_acls"))
            block_public_policy = self._bool_value(resource.properties.get("block_public_policy"))
            ignore_public_acls = self._bool_value(resource.properties.get("ignore_public_acls"))
            restrict_public_buckets = self._bool_value(resource.properties.get("restrict_public_buckets"))
        return {
            "bucket_reference": bucket_ref,
            "block_public_acls": block_public_acls,
            "block_public_policy": block_public_policy,
            "ignore_public_acls": ignore_public_acls,
            "restrict_public_buckets": restrict_public_buckets,
            "all_public_access_blocks_enabled": all(
                value is True
                for value in [block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets]
            ),
            "properties": resource.properties,
        }

    def _rds_instance_facts(self, resource: ResourceBlock) -> dict[str, Any]:
        if resource.resource_type == "AWS::RDS::DBInstance":
            engine = resource.properties.get("Engine")
            instance_class = resource.properties.get("DBInstanceClass")
            storage_encrypted = self._bool_value(resource.properties.get("StorageEncrypted"))
            kms_key_configured = bool(resource.properties.get("KmsKeyId"))
            publicly_accessible = self._bool_value(resource.properties.get("PubliclyAccessible"))
        else:
            engine = resource.properties.get("engine")
            instance_class = resource.properties.get("instance_class")
            storage_encrypted = self._bool_value(resource.properties.get("storage_encrypted"))
            kms_key_configured = bool(resource.properties.get("kms_key_id"))
            publicly_accessible = self._bool_value(resource.properties.get("publicly_accessible"))
        return {
            "engine": engine,
            "instance_class": instance_class,
            "storage_encrypted": storage_encrypted,
            "kms_key_configured": kms_key_configured,
            "publicly_accessible": publicly_accessible,
            "properties": resource.properties,
        }

    def _security_group_facts(self, resource: ResourceBlock) -> dict[str, Any]:
        if resource.resource_type == "AWS::EC2::SecurityGroup":
            ingress_rules = self._list_of_dicts(resource.properties.get("SecurityGroupIngress"))
        else:
            ingress_rules = self._list_of_dicts(resource.properties.get("ingress"))
        public_ports: list[int | str] = []
        public_ranges: list[str] = []
        ssh_open = False

        for ingress in ingress_rules:
            if resource.resource_type == "AWS::EC2::SecurityGroup":
                cidrs = self._ensure_list(ingress.get("CidrIp")) + self._ensure_list(ingress.get("CidrIpv6"))
                from_port = self._int_value(ingress.get("FromPort"))
                to_port = self._int_value(ingress.get("ToPort"))
            else:
                cidrs = self._ensure_list(ingress.get("cidr_blocks")) + self._ensure_list(ingress.get("ipv6_cidr_blocks"))
                from_port = self._int_value(ingress.get("from_port"))
                to_port = self._int_value(ingress.get("to_port"))
            if not any(cidr in {"0.0.0.0/0", "::/0"} for cidr in cidrs):
                continue
            if from_port is None or to_port is None:
                public_ranges.append("unknown")
                continue
            public_ranges.append(f"{from_port}-{to_port}")
            if from_port == to_port:
                public_ports.append(from_port)
            else:
                public_ports.append(f"{from_port}-{to_port}")
            if from_port <= 22 <= to_port:
                ssh_open = True

        return {
            "ingress_rule_count": len(ingress_rules),
            "public_ingress_ports": public_ports,
            "public_ingress_ranges": public_ranges,
            "ssh_open_to_world": ssh_open,
            "properties": resource.properties,
        }

    def _kubernetes_workload_facts(self, resource: ResourceBlock) -> dict[str, Any]:
        spec = resource.properties.get("spec", {}) if isinstance(resource.properties.get("spec"), dict) else {}
        template_spec = spec.get("template", {}).get("spec", {}) if isinstance(spec.get("template", {}), dict) else {}
        pod_spec = template_spec if template_spec else spec
        containers = pod_spec.get("containers", []) if isinstance(pod_spec.get("containers", []), list) else []
        run_as_non_root = self._extract_security_value(pod_spec, containers, "runAsNonRoot")
        privileged = self._extract_any_container_security_value(containers, "privileged")
        service_account = pod_spec.get("serviceAccountName")
        return {
            "container_count": len(containers),
            "run_as_non_root": run_as_non_root,
            "privileged": privileged,
            "service_account_name": service_account,
            "properties": resource.properties,
        }

    def _facts_to_text(self, resource: ResourceBlock, facts: dict[str, Any]) -> str:
        summary_lines = [
            f"Resource type: {resource.resource_type}",
            f"Resource name: {resource.resource_name}",
        ]
        if resource.line_number is not None:
            summary_lines.append(f"Declared at line: {resource.line_number}")

        for key, value in facts.items():
            if key in {"properties", "resource_type", "resource_name", "line_number"}:
                continue
            label = key.replace("_", " ").capitalize()
            summary_lines.append(f"{label}: {value}")

        summary_lines.append("Properties:")
        summary_lines.append(yaml.safe_dump(resource.properties, sort_keys=True).strip())
        return "\n".join(summary_lines)

    def _matches_s3_bucket(self, pab_resource: ResourceBlock, bucket_resource: ResourceBlock) -> bool:
        bucket_ref = str(pab_resource.properties.get("bucket", "")).strip()
        bucket_name = str(bucket_resource.properties.get("bucket", "")).strip()

        if not bucket_ref:
            return pab_resource.resource_name == bucket_resource.resource_name
        if bucket_ref == bucket_name:
            return True
        if bucket_resource.resource_name and bucket_resource.resource_name in bucket_ref:
            return True
        if bucket_name and bucket_name in bucket_ref:
            return True
        return False

    def _extract_logging_target_bucket(self, logging_block: Any) -> Any:
        blocks = self._list_of_dicts(logging_block)
        if not blocks:
            return None
        return blocks[0].get("target_bucket")

    def _all_public_access_flags_enabled(self, resource: ResourceBlock) -> bool:
        required = [
            self._bool_value(resource.properties.get("block_public_acls")),
            self._bool_value(resource.properties.get("block_public_policy")),
            self._bool_value(resource.properties.get("ignore_public_acls")),
            self._bool_value(resource.properties.get("restrict_public_buckets")),
        ]
        return all(value is True for value in required)

    def _cloudformation_public_access_enabled(self, config: Any) -> bool:
        if not isinstance(config, dict):
            return False
        required = [
            self._bool_value(config.get("BlockPublicAcls")),
            self._bool_value(config.get("BlockPublicPolicy")),
            self._bool_value(config.get("IgnorePublicAcls")),
            self._bool_value(config.get("RestrictPublicBuckets")),
        ]
        return all(value is True for value in required)

    def _extract_security_value(self, pod_spec: dict[str, Any], containers: list[dict[str, Any]], key: str) -> Any:
        pod_security = pod_spec.get("securityContext", {}) if isinstance(pod_spec.get("securityContext"), dict) else {}
        if key in pod_security:
            return pod_security.get(key)
        return self._extract_any_container_security_value(containers, key)

    def _extract_any_container_security_value(self, containers: list[dict[str, Any]], key: str) -> Any:
        for container in containers:
            security = container.get("securityContext", {}) if isinstance(container.get("securityContext"), dict) else {}
            if key in security:
                return security.get(key)
        return None

    def _bool_value(self, value: Any) -> bool | None:
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
