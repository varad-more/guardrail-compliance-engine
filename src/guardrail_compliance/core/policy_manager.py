from __future__ import annotations

from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .models import AutomatedReasoningPolicyInfo, GuardrailInfo
from ..policies.registry import PolicyRegistry
from ..utils.exceptions import GuardrailComplianceError, PolicyValidationError


class PolicyManager:
    """Manage Bedrock guardrails and Automated Reasoning policy lifecycle operations."""

    def __init__(self, *, region: str = "us-east-1", client: Any | None = None) -> None:
        self.region = region
        self.client = client or boto3.client("bedrock", region_name=region)

    # ---------------------------------------------------------------------
    # Guardrail management
    # ---------------------------------------------------------------------
    def create_compliance_guardrail(self, name: str, policy_config: dict[str, Any]) -> str:
        """Create a Bedrock guardrail with an automated-reasoning policy binding."""
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
        """Sync local policy YAML files to Bedrock guardrails; return {name: guardrail_id}."""
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
        """List all Bedrock guardrails in the account."""
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
        """Delete a Bedrock guardrail by ID."""
        try:
            self.client.delete_guardrail(guardrailIdentifier=guardrail_id)
        except (ClientError, BotoCoreError) as exc:
            raise GuardrailComplianceError(f"Unable to delete guardrail {guardrail_id}: {exc}") from exc

    # ---------------------------------------------------------------------
    # Automated Reasoning policy lifecycle
    # ---------------------------------------------------------------------
    def list_automated_reasoning_policies(self) -> list[AutomatedReasoningPolicyInfo]:
        """List all Automated Reasoning policies in the account."""
        try:
            response = self.client.list_automated_reasoning_policies()
        except (ClientError, BotoCoreError) as exc:
            raise GuardrailComplianceError(f"Unable to list automated reasoning policies: {exc}") from exc

        summaries = response.get("automatedReasoningPolicySummaries", [])
        return [
            AutomatedReasoningPolicyInfo(
                name=item.get("name", ""),
                policy_arn=item.get("policyArn", ""),
                policy_id=item.get("policyId"),
                version=str(item.get("version", "DRAFT")),
                description=item.get("description"),
                created_at=self._serialize_time(item.get("createdAt")),
                updated_at=self._serialize_time(item.get("updatedAt")),
            )
            for item in summaries
            if item.get("policyArn")
        ]

    def create_automated_reasoning_policy(
        self,
        *,
        name: str,
        description: str | None = None,
        policy_definition: dict[str, Any] | None = None,
        kms_key_id: str | None = None,
        tags: dict[str, str] | None = None,
    ) -> str:
        payload: dict[str, Any] = {
            "name": name,
        }
        if description:
            payload["description"] = description
        if policy_definition:
            payload["policyDefinition"] = policy_definition
        if kms_key_id:
            payload["kmsKeyId"] = kms_key_id
        if tags:
            payload["tags"] = self._tag_list(tags)

        try:
            response = self.client.create_automated_reasoning_policy(**payload)
        except (ClientError, BotoCoreError) as exc:
            raise GuardrailComplianceError(f"Unable to create automated reasoning policy '{name}': {exc}") from exc

        return response["policyArn"]

    def get_automated_reasoning_policy(self, policy_arn: str) -> AutomatedReasoningPolicyInfo:
        try:
            response = self.client.get_automated_reasoning_policy(policyArn=policy_arn)
        except (ClientError, BotoCoreError) as exc:
            raise GuardrailComplianceError(f"Unable to get automated reasoning policy {policy_arn}: {exc}") from exc

        return AutomatedReasoningPolicyInfo(
            name=response.get("name", ""),
            policy_arn=response.get("policyArn", policy_arn),
            policy_id=response.get("policyId"),
            version=str(response.get("version", "DRAFT")),
            description=response.get("description"),
            definition_hash=response.get("definitionHash"),
            created_at=self._serialize_time(response.get("createdAt")),
            updated_at=self._serialize_time(response.get("updatedAt")),
        )

    def start_automated_reasoning_ingest_build(
        self,
        *,
        policy_arn: str,
        source_content: str | bytes,
        document_name: str = "source-policy.txt",
        document_content_type: str = "txt",
        document_description: str | None = None,
    ) -> str:
        """Upload a source document and kick off an AR policy ingest build."""
        blob = source_content.encode("utf-8") if isinstance(source_content, str) else source_content
        document = {
            "document": blob,
            "documentContentType": document_content_type,
            "documentName": document_name,
        }
        if document_description:
            document["documentDescription"] = document_description

        try:
            response = self.client.start_automated_reasoning_policy_build_workflow(
                policyArn=policy_arn,
                buildWorkflowType="INGEST_CONTENT",
                sourceContent={
                    "workflowContent": {
                        "documents": [document],
                    }
                },
            )
        except (ClientError, BotoCoreError) as exc:
            raise GuardrailComplianceError(f"Unable to start policy build workflow for {policy_arn}: {exc}") from exc

        return response["buildWorkflowId"]

    def get_automated_reasoning_policy_build_workflow(
        self,
        *,
        policy_arn: str,
        workflow_id: str,
    ) -> dict[str, Any]:
        try:
            return self.client.get_automated_reasoning_policy_build_workflow(
                policyArn=policy_arn,
                buildWorkflowId=workflow_id,
            )
        except (ClientError, BotoCoreError) as exc:
            raise GuardrailComplianceError(
                f"Unable to fetch policy build workflow {workflow_id} for {policy_arn}: {exc}"
            ) from exc

    def start_automated_reasoning_ingest_build_from_file(
        self,
        *,
        policy_arn: str,
        source_file: Path,
        document_description: str | None = None,
    ) -> str:
        """Convenience wrapper: read a local file and start an ingest build."""
        suffix = source_file.suffix.lower()
        content_type = "pdf" if suffix == ".pdf" else "txt"
        payload = source_file.read_bytes() if content_type == "pdf" else source_file.read_text(encoding="utf-8")
        return self.start_automated_reasoning_ingest_build(
            policy_arn=policy_arn,
            source_content=payload,
            document_name=source_file.name,
            document_content_type=content_type,
            document_description=document_description,
        )

    def create_automated_reasoning_policy_version(self, *, policy_arn: str, definition_hash: str) -> str:
        """Freeze the current policy definition into a numbered version."""
        try:
            response = self.client.create_automated_reasoning_policy_version(
                policyArn=policy_arn,
                lastUpdatedDefinitionHash=definition_hash,
            )
        except (ClientError, BotoCoreError) as exc:
            raise GuardrailComplianceError(f"Unable to create policy version for {policy_arn}: {exc}") from exc

        return str(response["version"])

    def create_automated_reasoning_policy_version_from_latest(self, *, policy_arn: str) -> str:
        """Fetch the latest definition hash and create a version from it."""
        policy = self.get_automated_reasoning_policy(policy_arn)
        if not policy.definition_hash:
            raise GuardrailComplianceError(f"Policy {policy_arn} has no definition hash; cannot version it.")
        return self.create_automated_reasoning_policy_version(policy_arn=policy_arn, definition_hash=policy.definition_hash)

    def export_automated_reasoning_policy_version(self, policy_version_arn: str) -> dict[str, Any]:
        """Export a versioned policy definition as a JSON-serialisable dict."""
        try:
            response = self.client.export_automated_reasoning_policy_version(policyArn=policy_version_arn)
        except (ClientError, BotoCoreError) as exc:
            raise GuardrailComplianceError(f"Unable to export policy version {policy_version_arn}: {exc}") from exc

        return response.get("policyDefinition", {})

    # ---------------------------------------------------------------------
    # helpers
    # ---------------------------------------------------------------------
    def _tag_list(self, tags: dict[str, str]) -> list[dict[str, str]]:
        return [{"key": str(key), "value": str(value)} for key, value in tags.items()]

    def _serialize_time(self, value: Any) -> str | None:
        if value is None:
            return None
        if hasattr(value, "isoformat"):
            return value.isoformat()
        return str(value)
