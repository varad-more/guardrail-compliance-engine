install:
	python -m pip install -e '.[dev]'

test:
	python -m pytest

scan-example:
	guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic --no-bedrock

smoke-bedrock:
	python scripts/bedrock_smoke.py
