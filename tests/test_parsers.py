from pathlib import Path

from guardrail_compliance.parsers.cloudformation import CloudFormationParser
from guardrail_compliance.parsers.kubernetes import KubernetesParser
from guardrail_compliance.parsers.terraform import TerraformParser


def test_terraform_parser_extracts_resources(project_root: Path) -> None:
    parser = TerraformParser()
    file_path = project_root / "examples/terraform/noncompliant-s3.tf"

    resources = parser.parse(file_path)

    assert len(resources) == 2
    assert resources[0].resource_type == "aws_s3_bucket"
    assert resources[0].resource_name == "data_lake"
    assert 'resource "aws_s3_bucket" "data_lake"' in resources[0].raw_text


def test_cloudformation_parser_extracts_resources(project_root: Path) -> None:
    parser = CloudFormationParser()
    file_path = project_root / "examples/cloudformation/noncompliant-stack.yaml"

    resources = parser.parse(file_path)

    assert len(resources) == 2
    assert resources[0].resource_type == "AWS::S3::Bucket"
    assert resources[0].resource_name == "PublicBucket"



def test_kubernetes_parser_extracts_documents(project_root: Path) -> None:
    parser = KubernetesParser()
    file_path = project_root / "examples/kubernetes/compliant-deployment.yaml"

    resources = parser.parse(file_path)

    assert len(resources) == 2
    assert resources[0].resource_type == "Deployment"
    assert resources[0].resource_name == "compliant-api"
