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
        usage = response.get("usage", {})
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
                translation = payload.get("translation", {}) if isinstance(payload.get("translation"), dict) else {}
                confidence = translation.get("confidence")
                title = self._title_for_kind(kind)
                rule_id = self._rule_id(kind, payload)
                message = self._message_for_kind(kind, payload)
                proof = self._build_proof(kind, payload, confidence, action)
                parsed.append(
                    Finding(
                        rule_id=rule_id,
                        title=title,
                        severity=self._severity_for_kind(kind),
                        status=self._status_for_kind(kind),
                        message=message,
                        proof=proof,
                        remediation=self._remediation_for_kind(kind),
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

    def _title_for_kind(self, kind: str) -> str:
        return {
            "valid": "Automated reasoning: valid",
            "invalid": "Automated reasoning: invalid",
            "satisfiable": "Automated reasoning: satisfiable",
            "impossible": "Automated reasoning: impossible",
            "translationAmbiguous": "Automated reasoning: translation ambiguous",
            "tooComplex": "Automated reasoning: too complex",
            "noTranslations": "Automated reasoning: no translations",
        }.get(kind, f"Automated reasoning: {kind}")

    def _rule_id(self, kind: str, payload: dict[str, Any]) -> str:
        rule_ids = [item.get("identifier") for item in payload.get("supportingRules", []) if item.get("identifier")]
        rule_ids += [item.get("identifier") for item in payload.get("contradictingRules", []) if item.get("identifier")]
        if rule_ids:
            return ",".join(rule_ids)
        return kind.upper()

    def _message_for_kind(self, kind: str, payload: dict[str, Any]) -> str:
        translations = self._translation_lines(payload.get("translation", {}))
        if kind == "valid":
            return "Claims are logically supported by the policy." if translations else "Input is logically valid against the policy."
        if kind == "invalid":
            return "Claims contradict the policy rules."
        if kind == "satisfiable":
            return "Claims could be true or false depending on missing assumptions."
        if kind == "impossible":
            return "The translated premises or claims are logically impossible under the policy."
        if kind == "translationAmbiguous":
            return "The input can be translated into multiple logical interpretations."
        if kind == "tooComplex":
            return "The input is too complex for automated reasoning evaluation."
        if kind == "noTranslations":
            return "No policy-relevant statements could be translated from the input."
        return f"Automated reasoning returned a {kind} result."

    def _build_proof(self, kind: str, payload: dict[str, Any], confidence: Any, action: str) -> str:
        proof_lines: list[str] = []
        if confidence is not None:
            proof_lines.append(f"Translation confidence: {confidence}")

        translation_lines = self._translation_lines(payload.get("translation", {}))
        if translation_lines:
            proof_lines.extend(translation_lines)

        rules = [item.get("identifier") for item in payload.get("supportingRules", []) if item.get("identifier")]
        if rules:
            proof_lines.append(f"Supporting rules: {', '.join(rules)}")

        contradictions = [item.get("identifier") for item in payload.get("contradictingRules", []) if item.get("identifier")]
        if contradictions:
            proof_lines.append(f"Contradicting rules: {', '.join(contradictions)}")

        for label, key in (
            ("Claims-true scenario", "claimsTrueScenario"),
            ("Claims-false scenario", "claimsFalseScenario"),
            ("Difference scenario", "differenceScenarios"),
        ):
            scenario_text = self._scenario_lines(payload.get(key))
            if scenario_text:
                proof_lines.append(f"{label}: {scenario_text}")

        if not proof_lines:
            proof_lines.append(f"ApplyGuardrail action={action}; finding type={kind}")
        return "\n".join(proof_lines)

    def _remediation_for_kind(self, kind: str) -> str | None:
        if kind in {"translationAmbiguous", "noTranslations", "tooComplex"}:
            return "Normalize the resource facts further and reduce ambiguity before retrying Bedrock evaluation."
        return None

    def _translation_lines(self, translation: Any) -> list[str]:
        if not isinstance(translation, dict):
            return []
        lines: list[str] = []
        premises = [item.get("naturalLanguage") for item in translation.get("premises", []) if item.get("naturalLanguage")]
        claims = [item.get("naturalLanguage") for item in translation.get("claims", []) if item.get("naturalLanguage")]
        untranslated_premises = [item.get("text") for item in translation.get("untranslatedPremises", []) if item.get("text")]
        untranslated_claims = [item.get("text") for item in translation.get("untranslatedClaims", []) if item.get("text")]
        if premises:
            lines.append(f"Premises: {' | '.join(premises)}")
        if claims:
            lines.append(f"Claims: {' | '.join(claims)}")
        if untranslated_premises:
            lines.append(f"Untranslated premises: {' | '.join(untranslated_premises)}")
        if untranslated_claims:
            lines.append(f"Untranslated claims: {' | '.join(untranslated_claims)}")
        return lines

    def _scenario_lines(self, scenario: Any) -> str | None:
        if isinstance(scenario, dict):
            statements = scenario.get("statements", [])
            values = [item.get("naturalLanguage") for item in statements if item.get("naturalLanguage")]
            if values:
                return " | ".join(values)
        if isinstance(scenario, list):
            combined: list[str] = []
            for item in scenario:
                text = self._scenario_lines(item)
                if text:
                    combined.append(text)
            if combined:
                return " || ".join(combined)
        return None
