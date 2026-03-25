install:
	uv sync --extra dev

test:
	uv run pytest

scan-example:
	uv run guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic

smoke-bedrock:
	uv run python scripts/bedrock_smoke.py
