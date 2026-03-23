from __future__ import annotations

import asyncio
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .models import ComplianceResult, Finding
from ..utils.exceptions import BedrockEvaluationError


class BedrockGuardrailClient:
    """Thin wrapper around the Bedrock ApplyGuardrail runtime API."""

    FINDING_KINDS = (
        "invalid",
        "impossible",
        "translationAmbiguous",
        "tooComplex",
        "noTranslations",
        "satisfiable",
        "valid",
    )

    def __init__(
        self,
        guardrail_id: str,
        guardrail_version: str = "DRAFT",
        *,
        region: str = "us-east-1",
        client: Any | None = None,
    ) -> None:
        self.guardrail_id = guardrail_id
        self.guardrail_version = guardrail_version
        self.region = region
        self.client = client or boto3.client("bedrock-runtime", region_name=region)

    async def evaluate(self, content: str, content_type: str = "terraform") -> ComplianceResult:
        try:
            response = await asyncio.to_thread(
                self.client.apply_guardrail,
                guardrailIdentifier=self.guardrail_id,
                guardrailVersion=self.guardrail_version,
                source="INPUT",
                content=self._build_content_blocks(content),
                outputScope="FULL",
            )
        except (ClientError, BotoCoreError) as exc:
            raise BedrockEvaluationError(f"ApplyGuardrail failed: {exc}") from exc

        findings = self._parse_assessment(response)
        usage = {}
        for assessment in response.get("assessments", []):
            usage.update(assessment.get("invocationMetrics", {}).get("usage", {}))

        return ComplianceResult(
            action=response.get("action", "UNKNOWN"),
            findings=findings,
            raw_response=response,
            usage=usage,
        )

    def _parse_assessment(self, response: dict[str, Any]) -> list[Finding]:
        parsed: list[Finding] = []
        action = response.get("action", "UNKNOWN")

        for assessment in response.get("assessments", []):
            policy_assessment = assessment.get("automatedReasoningPolicy") or {}
            for raw_finding in policy_assessment.get("findings", []):
                kind, payload = self._unpack_finding(raw_finding)
                status = self._status_for_kind(kind)
                severity = self._severity_for_kind(kind)
                title = self._coalesce(payload, [
                    "ruleName",
                    "policyName",
                    "title",
                    "summary",
                    "type",
                ]) or kind
                message = self._coalesce(payload, [
                    "explanation",
                    "message",
                    "claim",
                    "issue",
                    "summary",
                ]) or f"Automated reasoning returned a {kind} result."
                proof = self._coalesce(payload, [
                    "logicExplanation",
                    "proof",
                    "justification",
                    "supportingRules",
                    "supportingAssignments",
                ])
                parsed.append(
                    Finding(
                        rule_id=str(self._coalesce(payload, ["ruleId", "policyId", "id"]) or kind.upper()),
                        title=str(title),
                        severity=severity,
                        status=status,
                        message=str(message),
                        proof=str(proof) if proof is not None else f"ApplyGuardrail action={action}",
                        remediation=None,
                        source="bedrock",
                        raw=raw_finding,
                    )
                )

        return parsed

    def _build_content_blocks(self, text: str) -> list[dict[str, Any]]:
        return [{"text": {"text": text}}]

    def _unpack_finding(self, raw_finding: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        for kind in self.FINDING_KINDS:
            if kind in raw_finding:
                payload = raw_finding.get(kind) or {}
                return kind, payload if isinstance(payload, dict) else {"value": payload}
        return "unknown", raw_finding

    def _status_for_kind(self, kind: str) -> str:
        if kind == "valid":
            return "PASS"
        if kind in {"satisfiable", "translationAmbiguous", "noTranslations"}:
            return "WARN"
        return "FAIL"

    def _severity_for_kind(self, kind: str) -> str:
        return {
            "valid": "LOW",
            "satisfiable": "MEDIUM",
            "translationAmbiguous": "MEDIUM",
            "noTranslations": "MEDIUM",
            "tooComplex": "HIGH",
            "impossible": "HIGH",
            "invalid": "HIGH",
        }.get(kind, "MEDIUM")

    def _coalesce(self, payload: dict[str, Any], keys: list[str]) -> str | None:
        for key in keys:
            value = payload.get(key)
            if value is None:
                continue
            if isinstance(value, list):
                return ", ".join(str(item) for item in value if item is not None)
            if isinstance(value, dict):
                return "; ".join(f"{k}={v}" for k, v in value.items())
            return str(value)
        return None
