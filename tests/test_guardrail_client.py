import asyncio

from guardrail_compliance.core.guardrail_client import BedrockGuardrailClient


class StubRuntimeClient:
    def __init__(self, response):
        self.response = response

    def apply_guardrail(self, **kwargs):
        return self.response


async def _evaluate(response):
    client = BedrockGuardrailClient(
        guardrail_id="gr-test",
        guardrail_version="1",
        client=StubRuntimeClient(response),
    )
    return await client.evaluate("normalized facts")



def test_guardrail_client_parses_invalid_finding() -> None:
    response = {
        "action": "NONE",
        "usage": {"automatedReasoningPolicyUnits": 1},
        "assessments": [
            {
                "automatedReasoningPolicy": {
                    "findings": [
                        {
                            "invalid": {
                                "translation": {
                                    "premises": [{"naturalLanguage": "S3 bucket has no encryption"}],
                                    "claims": [{"naturalLanguage": "S3 bucket is compliant"}],
                                    "confidence": 0.93,
                                },
                                "contradictingRules": [{"identifier": "SOC2-ENC-001", "policyVersionArn": "arn:...:1"}],
                            }
                        }
                    ]
                }
            }
        ],
    }

    result = asyncio.run(_evaluate(response))

    assert result.usage["automatedReasoningPolicyUnits"] == 1
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "SOC2-ENC-001"
    assert finding.status == "FAIL"
    assert "contradict" in finding.message.lower()
    assert "Translation confidence: 0.93" in (finding.proof or "")



def test_guardrail_client_parses_ambiguous_finding_with_remediation() -> None:
    response = {
        "action": "NONE",
        "assessments": [
            {
                "automatedReasoningPolicy": {
                    "findings": [
                        {
                            "translationAmbiguous": {
                                "differenceScenarios": [
                                    {
                                        "statements": [
                                            {"naturalLanguage": "Bucket logging may be enabled"},
                                            {"naturalLanguage": "Bucket logging may be disabled"},
                                        ]
                                    }
                                ]
                            }
                        }
                    ]
                }
            }
        ],
    }

    result = asyncio.run(_evaluate(response))

    finding = result.findings[0]
    assert finding.status == "WARN"
    assert finding.remediation is not None
    assert "Difference scenario" in (finding.proof or "")
