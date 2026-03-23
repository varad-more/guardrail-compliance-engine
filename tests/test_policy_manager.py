from pathlib import Path

from guardrail_compliance.core.policy_manager import PolicyManager


class StubBedrockControlClient:
    def __init__(self):
        self.created: list[dict] = []

    def create_guardrail(self, **kwargs):
        self.created.append(kwargs)
        return {"guardrailId": "gr-123"}

    def list_guardrails(self):
        return {
            "guardrails": [
                {
                    "name": "existing-policy",
                    "guardrailId": "gr-existing",
                    "version": "1",
                    "guardrailArn": "arn:aws:bedrock:us-east-1:123456789012:guardrail/gr-existing",
                    "status": "READY",
                }
            ]
        }

    def delete_guardrail(self, **kwargs):
        self.deleted = kwargs



def test_policy_manager_creates_guardrail() -> None:
    client = StubBedrockControlClient()
    manager = PolicyManager(region="us-east-1", client=client)

    guardrail_id = manager.create_compliance_guardrail(
        "soc2-basic",
        {
            "policy_arns": ["arn:aws:bedrock:us-east-1:123456789012:automated-reasoning-policy/test:1"],
            "confidence_threshold": 0.8,
            "cross_region_profile": "us.guardrail.v1:0",
        },
    )

    assert guardrail_id == "gr-123"
    assert client.created[0]["automatedReasoningPolicyConfig"]["policies"][0].endswith(":1")



def test_policy_manager_sync_returns_empty_when_no_bedrock_bindings(tmp_path: Path) -> None:
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    (policy_dir / "custom.yaml").write_text(
        """
name: custom
version: \"0.1.0\"
framework: Custom
rules:
  - id: CUSTOM-1
    title: Example
    description: Example
    severity: LOW
    resource_types:
      - aws_s3_bucket
    constraint: Example
""".strip(),
        encoding="utf-8",
    )
    manager = PolicyManager(region="us-east-1", client=StubBedrockControlClient())

    mapping = manager.sync_policies(policy_dir)

    assert mapping == {}
