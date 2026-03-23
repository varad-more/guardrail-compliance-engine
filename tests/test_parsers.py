from pathlib import Path

from guardrail_compliance.parsers.terraform import TerraformParser


def test_terraform_parser_extracts_resources(project_root: Path) -> None:
    parser = TerraformParser()
    file_path = project_root / "examples/terraform/noncompliant-s3.tf"

    resources = parser.parse(file_path)

    assert len(resources) == 2
    assert resources[0].resource_type == "aws_s3_bucket"
    assert resources[0].resource_name == "data_lake"
    assert "resource \"aws_s3_bucket\" \"data_lake\"" in resources[0].raw_text
