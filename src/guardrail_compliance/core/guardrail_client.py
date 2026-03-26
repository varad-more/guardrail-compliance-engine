from __future__ import annotations

import asyncio
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .models import ComplianceResult, Finding
from ..utils.exceptions import BedrockEvaluationError


class BedrockGuardrailClient:
    """Thin wrapper around the Bedrock ``ApplyGuardrail`` runtime API.

    Sends normalised resource text to Bedrock and parses the automated-reasoning
    response into structured ``Finding`` objects.
    """

    # All possible automated-reasoning finding types returned by the API.
    FINDING_KINDS = (
        "invalid", "impossible", "translationAmbiguous",
        "tooComplex", "noTranslations", "satisfiable", "valid",
    )

    # Lookup tables — one line per finding kind keeps the mapping scannable.
    _STATUS: dict[str, str] = {
        "valid": "PASS",
        "satisfiable": "WARN", "translationAmbiguous": "WARN", "noTranslations": "WARN",
        "invalid": "FAIL", "impossible": "FAIL", "tooComplex": "FAIL",
    }
    _SEVERITY: dict[str, str] = {
        "valid": "LOW",
        "satisfiable": "MEDIUM", "translationAmbiguous": "MEDIUM", "noTranslations": "MEDIUM",
        "tooComplex": "HIGH", "impossible": "HIGH", "invalid": "HIGH",
    }
    _TITLE: dict[str, str] = {
        "valid": "Automated reasoning: valid",
        "invalid": "Automated reasoning: invalid",
        "satisfiable": "Automated reasoning: satisfiable",
        "impossible": "Automated reasoning: impossible",
        "translationAmbiguous": "Automated reasoning: translation ambiguous",
        "tooComplex": "Automated reasoning: too complex",
        "noTranslations": "Automated reasoning: no translations",
    }
    _MESSAGE: dict[str, str] = {
        "valid": "Claims are logically supported by the policy.",
        "invalid": "Claims contradict the policy rules.",
        "satisfiable": "Claims could be true or false depending on missing assumptions.",
        "impossible": "The translated premises or claims are logically impossible under the policy.",
        "translationAmbiguous": "The input can be translated into multiple logical interpretations.",
        "tooComplex": "The input is too complex for automated reasoning evaluation.",
        "noTranslations": "No policy-relevant statements could be translated from the input.",
    }
    _REMEDIABLE_KINDS = {"translationAmbiguous", "noTranslations", "tooComplex"}

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

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def evaluate(self, content: str, content_type: str = "terraform") -> ComplianceResult:
        """Call ``ApplyGuardrail`` and return a parsed ``ComplianceResult``."""
        try:
            response = await asyncio.to_thread(
                self.client.apply_guardrail,
                guardrailIdentifier=self.guardrail_id,
                guardrailVersion=self.guardrail_version,
                source="OUTPUT",
                content=[{"text": {"text": content}}],
                outputScope="FULL",
            )
        except (ClientError, BotoCoreError) as exc:
            raise BedrockEvaluationError(f"ApplyGuardrail failed: {exc}") from exc

        findings = self._parse_assessments(response)
        usage = response.get("usage", {})
        for assessment in response.get("assessments", []):
            usage.update(assessment.get("invocationMetrics", {}).get("usage", {}))

        return ComplianceResult(
            action=response.get("action", "UNKNOWN"),
            findings=findings,
            raw_response=response,
            usage=usage,
        )

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_assessments(self, response: dict[str, Any]) -> list[Finding]:
        """Walk all assessments in the response and build Finding objects."""
        findings: list[Finding] = []
        action = response.get("action", "UNKNOWN")

        for assessment in response.get("assessments", []):
            ar_policy = assessment.get("automatedReasoningPolicy") or {}
            for raw in ar_policy.get("findings", []):
                kind, payload = self._unpack_finding(raw)
                translation = payload.get("translation") if isinstance(payload.get("translation"), dict) else {}
                findings.append(Finding(
                    rule_id=self._rule_id(payload),
                    title=self._TITLE.get(kind, f"Automated reasoning: {kind}"),
                    severity=self._SEVERITY.get(kind, "MEDIUM"),
                    status=self._STATUS.get(kind, "FAIL"),
                    message=self._message(kind, payload),
                    proof=self._build_proof(kind, payload, (translation or {}).get("confidence"), action),
                    remediation=("Normalize the resource facts further and reduce ambiguity before retrying."
                                 if kind in self._REMEDIABLE_KINDS else None),
                    source="bedrock",
                    raw=raw,
                ))

        return findings

    def _unpack_finding(self, raw: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Extract the (kind, payload) pair from a raw finding dict."""
        for kind in self.FINDING_KINDS:
            if kind in raw:
                payload = raw.get(kind) or {}
                return kind, payload if isinstance(payload, dict) else {"value": payload}
        return "unknown", raw

    # ------------------------------------------------------------------
    # Finding field builders
    # ------------------------------------------------------------------

    @staticmethod
    def _rule_id(payload: dict[str, Any]) -> str:
        """Derive the rule ID from supporting/contradicting rules, or fall back to the kind."""
        ids = [
            item.get("identifier")
            for key in ("supportingRules", "contradictingRules")
            for item in payload.get(key, [])
            if item.get("identifier")
        ]
        return ",".join(ids) if ids else "UNKNOWN"

    def _message(self, kind: str, payload: dict[str, Any]) -> str:
        """Return a human-readable message for the finding kind."""
        if kind == "valid" and not self._translation_lines(payload.get("translation", {})):
            return "Input is logically valid against the policy."
        return self._MESSAGE.get(kind, f"Automated reasoning returned a {kind} result.")

    def _build_proof(self, kind: str, payload: dict[str, Any], confidence: Any, action: str) -> str:
        """Assemble a proof string from translation, rules, and scenario data."""
        lines: list[str] = []
        if confidence is not None:
            lines.append(f"Translation confidence: {confidence}")

        lines.extend(self._translation_lines(payload.get("translation", {})))

        for label, key in (("Supporting rules", "supportingRules"), ("Contradicting rules", "contradictingRules")):
            ids = [item.get("identifier") for item in payload.get(key, []) if item.get("identifier")]
            if ids:
                lines.append(f"{label}: {', '.join(ids)}")

        for label, key in (
            ("Claims-true scenario", "claimsTrueScenario"),
            ("Claims-false scenario", "claimsFalseScenario"),
            ("Difference scenario", "differenceScenarios"),
        ):
            text = self._format_scenario(payload.get(key))
            if text:
                lines.append(f"{label}: {text}")

        return "\n".join(lines) if lines else f"ApplyGuardrail action={action}; finding type={kind}"

    # ------------------------------------------------------------------
    # Translation & scenario helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _translation_lines(translation: Any) -> list[str]:
        """Extract premise, claim, and untranslated items from a translation dict."""
        if not isinstance(translation, dict):
            return []
        lines: list[str] = []
        for label, entries_key, item_key in (
            ("Premises", "premises", "naturalLanguage"),
            ("Claims", "claims", "naturalLanguage"),
            ("Untranslated premises", "untranslatedPremises", "text"),
            ("Untranslated claims", "untranslatedClaims", "text"),
        ):
            items = [item[item_key] for item in translation.get(entries_key, []) if item.get(item_key)]
            if items:
                lines.append(f"{label}: {' | '.join(items)}")
        return lines

    @classmethod
    def _format_scenario(cls, scenario: Any) -> str | None:
        """Recursively format scenario statements into a pipe-delimited string."""
        if isinstance(scenario, dict):
            values = [s["naturalLanguage"] for s in scenario.get("statements", []) if s.get("naturalLanguage")]
            return " | ".join(values) if values else None
        if isinstance(scenario, list):
            parts = [cls._format_scenario(item) for item in scenario]
            combined = [p for p in parts if p]
            return " || ".join(combined) if combined else None
        return None
