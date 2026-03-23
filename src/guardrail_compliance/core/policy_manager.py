from __future__ import annotations

from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .models import GuardrailInfo
from ..policies.registry import PolicyRegistry
from ..utils.exceptions import GuardrailComplianceError, PolicyValidationError


class PolicyManager:
    """Manage Bedrock guardrails that reference versioned Automated Reasoning policies."""

    def __init__(self, *, region: str = "us-east-1", client: Any | None = None) -> None:
        self.region = region
        self.client = client or boto3.client("bedrock", region_name=region)

    def create_compliance_guardrail(self, name: str, policy_config: dict[str, Any]) -> str:
        policy_arns = policy_config.get("policy_arns") or policy_config.get("policies") or []
        if not policy_arns:
            raise PolicyValidationError("policy_config must include at least one versioned Automated Reasoning policy ARN")

        response = self.client.create_guardrail(
            name=name,
            description=policy_config.get("description", f"Compliance policy guardrail: {name}"),
            automatedReasoningPolicyConfig={
                "policies": policy_arns,
                "confidenceThreshold": float(policy_config.get("confidence_threshold", 0.8)),
            },
            crossRegionConfig={
                "guardrailProfileIdentifier": policy_config.get("cross_region_profile", "us.guardrail.v1:0")
            },
            blockedInputMessaging=policy_config.get("blocked_input_message", "COMPLIANCE_REVIEW_REQUIRED"),
            blockedOutputsMessaging=policy_config.get("blocked_output_message", "COMPLIANCE_REVIEW_REQUIRED"),
            tags=self._tag_list(policy_config.get("tags") or {"compliance-engine": "true"}),
        )
        return response["guardrailId"]

    def sync_policies(self, policy_dir: Path) -> dict[str, str]:
        registry = PolicyRegistry(policy_dir)
        mapping: dict[str, str] = {}
        policies = registry.all()
        candidates = [policy for policy in policies if policy.guardrail_id or policy.automated_reasoning_policy_arn]
        if not candidates:
            return mapping

        existing = {item.name: item for item in self.list_compliance_guardrails()}

        for policy in policies:
            if policy.guardrail_id:
                mapping[policy.name] = policy.guardrail_id
                continue
            if not policy.automated_reasoning_policy_arn:
                continue
            if policy.name in existing:
                mapping[policy.name] = existing[policy.name].guardrail_id
                continue
            mapping[policy.name] = self.create_compliance_guardrail(
                policy.name,
                {
                    "policy_arns": [policy.automated_reasoning_policy_arn],
                    "confidence_threshold": policy.confidence_threshold,
                    "cross_region_profile": policy.cross_region_profile,
                    "description": policy.description,
                    "tags": {
                        "compliance-engine": "true",
                        "framework": policy.framework,
                        "policy-name": policy.name,
                    },
                },
            )

        return mapping

    def list_compliance_guardrails(self) -> list[GuardrailInfo]:
        try:
            response = self.client.list_guardrails()
        except (ClientError, BotoCoreError) as exc:
            raise GuardrailComplianceError(f"Unable to list guardrails: {exc}") from exc

        summaries = response.get("guardrails") or response.get("guardrailSummaries") or []
        results: list[GuardrailInfo] = []
        for summary in summaries:
            name = summary.get("name") or summary.get("guardrailName")
            if not name:
                continue
            results.append(
                GuardrailInfo(
                    name=name,
                    guardrail_id=summary.get("id") or summary.get("guardrailId"),
                    version=str(summary.get("version") or summary.get("guardrailVersion") or "DRAFT"),
                    arn=summary.get("arn") or summary.get("guardrailArn"),
                    status=summary.get("status"),
                )
            )
        return results

    def delete_guardrail(self, guardrail_id: str) -> None:
        try:
            self.client.delete_guardrail(guardrailIdentifier=guardrail_id)
        except (ClientError, BotoCoreError) as exc:
            raise GuardrailComplianceError(f"Unable to delete guardrail {guardrail_id}: {exc}") from exc

    def _tag_list(self, tags: dict[str, str]) -> list[dict[str, str]]:
        return [{"key": str(key), "value": str(value)} for key, value in tags.items()]
