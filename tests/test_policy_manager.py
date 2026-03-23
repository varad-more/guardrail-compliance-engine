from pathlib import Path

from guardrail_compliance.core.policy_manager import PolicyManager


class StubBedrockControlClient:
    def __init__(self):
        self.created_guardrails: list[dict] = []
        self.created_ar_policies: list[dict] = []
        self.started_builds: list[dict] = []

    def create_guardrail(self, **kwargs):
        self.created_guardrails.append(kwargs)
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

    def list_automated_reasoning_policies(self):
        return {
            "automatedReasoningPolicySummaries": [
                {
                    "policyArn": "arn:aws:bedrock:us-east-1:123456789012:automated-reasoning-policy/demo",
                    "policyId": "demo",
                    "name": "demo-policy",
                    "description": "demo",
                    "version": "DRAFT",
                }
            ]
        }

    def create_automated_reasoning_policy(self, **kwargs):
        self.created_ar_policies.append(kwargs)
        return {
            "policyArn": "arn:aws:bedrock:us-east-1:123456789012:automated-reasoning-policy/new",
            "name": kwargs["name"],
            "version": "DRAFT",
            "definitionHash": "hash-abc",
        }

    def get_automated_reasoning_policy(self, **kwargs):
        return {
            "policyArn": kwargs["policyArn"],
            "policyId": "demo",
            "name": "demo-policy",
            "version": "DRAFT",
            "definitionHash": "hash-abc",
            "description": "demo",
        }

    def start_automated_reasoning_policy_build_workflow(self, **kwargs):
        self.started_builds.append(kwargs)
        return {
            "policyArn": kwargs["policyArn"],
            "buildWorkflowId": "wf-001",
        }

    def get_automated_reasoning_policy_build_workflow(self, **kwargs):
        return {
            "policyArn": kwargs["policyArn"],
            "buildWorkflowId": kwargs["buildWorkflowId"],
            "status": "COMPLETED",
            "buildWorkflowType": "INGEST_CONTENT",
        }

    def create_automated_reasoning_policy_version(self, **kwargs):
        return {
            "policyArn": kwargs["policyArn"],
            "version": "1",
            "definitionHash": kwargs["lastUpdatedDefinitionHash"],
            "name": "demo-policy",
        }

    def export_automated_reasoning_policy_version(self, **kwargs):
        return {
            "policyDefinition": {
                "version": "1.0",
                "variables": [],
                "rules": [],
                "types": [],
            }
        }



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
    assert client.created_guardrails[0]["automatedReasoningPolicyConfig"]["policies"][0].endswith(":1")



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



def test_policy_manager_automated_reasoning_lifecycle(tmp_path: Path) -> None:
    client = StubBedrockControlClient()
    manager = PolicyManager(region="us-east-1", client=client)

    policies = manager.list_automated_reasoning_policies()
    assert policies[0].name == "demo-policy"

    policy_arn = manager.create_automated_reasoning_policy(name="new-policy", description="desc")
    assert policy_arn.endswith("/new")

    source = tmp_path / "source.txt"
    source.write_text("if condition then result", encoding="utf-8")
    workflow_id = manager.start_automated_reasoning_ingest_build_from_file(policy_arn=policy_arn, source_file=source)
    assert workflow_id == "wf-001"

    status = manager.get_automated_reasoning_policy_build_workflow(policy_arn=policy_arn, workflow_id=workflow_id)
    assert status["status"] == "COMPLETED"

    version = manager.create_automated_reasoning_policy_version_from_latest(policy_arn=policy_arn)
    assert version == "1"

    exported = manager.export_automated_reasoning_policy_version(f"{policy_arn}:1")
    assert exported["version"] == "1.0"
