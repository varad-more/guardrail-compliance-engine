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

        if resource.resource_type == "aws_s3_bucket":
            facts.update(self._s3_bucket_facts(resource, resources_in_file))
        elif resource.resource_type == "aws_s3_bucket_public_access_block":
            facts.update(self._s3_public_access_block_facts(resource))
        elif resource.resource_type == "aws_db_instance":
            facts.update(self._rds_instance_facts(resource))
        elif resource.resource_type == "aws_security_group":
            facts.update(self._security_group_facts(resource))
        else:
            facts["properties"] = resource.properties

        return facts

    def _s3_bucket_facts(self, resource: ResourceBlock, resources_in_file: list[ResourceBlock]) -> dict[str, Any]:
        bucket_name = resource.properties.get("bucket")
        acl = resource.properties.get("acl", "private")
        pab_resources = [
            item for item in resources_in_file if item.resource_type == "aws_s3_bucket_public_access_block"
        ]
        matched_pabs = [item for item in pab_resources if self._matches_s3_bucket(item, resource)]
        encryption_block = resource.properties.get("server_side_encryption_configuration")
        logging_block = resource.properties.get("logging")

        return {
            "bucket_name": bucket_name,
            "acl": acl,
            "encryption_configured": bool(encryption_block),
            "logging_configured": bool(logging_block),
            "logging_target_bucket": self._extract_logging_target_bucket(logging_block),
            "public_access_block_present": bool(matched_pabs),
            "public_access_block_resources": [item.resource_name for item in matched_pabs],
            "public_access_block_all_enabled": any(self._all_public_access_flags_enabled(item) for item in matched_pabs),
            "properties": resource.properties,
        }

    def _s3_public_access_block_facts(self, resource: ResourceBlock) -> dict[str, Any]:
        bucket_ref = resource.properties.get("bucket")
        return {
            "bucket_reference": bucket_ref,
            "block_public_acls": self._bool_value(resource.properties.get("block_public_acls")),
            "block_public_policy": self._bool_value(resource.properties.get("block_public_policy")),
            "ignore_public_acls": self._bool_value(resource.properties.get("ignore_public_acls")),
            "restrict_public_buckets": self._bool_value(resource.properties.get("restrict_public_buckets")),
            "all_public_access_blocks_enabled": self._all_public_access_flags_enabled(resource),
            "properties": resource.properties,
        }

    def _rds_instance_facts(self, resource: ResourceBlock) -> dict[str, Any]:
        return {
            "engine": resource.properties.get("engine"),
            "instance_class": resource.properties.get("instance_class"),
            "storage_encrypted": self._bool_value(resource.properties.get("storage_encrypted")),
            "kms_key_configured": bool(resource.properties.get("kms_key_id")),
            "publicly_accessible": self._bool_value(resource.properties.get("publicly_accessible")),
            "properties": resource.properties,
        }

    def _security_group_facts(self, resource: ResourceBlock) -> dict[str, Any]:
        ingress_rules = self._list_of_dicts(resource.properties.get("ingress"))
        public_ports: list[int | str] = []
        public_ranges: list[str] = []
        ssh_open = False

        for ingress in ingress_rules:
            cidrs = self._ensure_list(ingress.get("cidr_blocks")) + self._ensure_list(ingress.get("ipv6_cidr_blocks"))
            if not any(cidr in {"0.0.0.0/0", "::/0"} for cidr in cidrs):
                continue
            from_port = self._int_value(ingress.get("from_port"))
            to_port = self._int_value(ingress.get("to_port"))
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
