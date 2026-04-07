install:
	python -m pip install -e '.[dev]'

test:
	python -m pytest

lint:
	ruff check src tests

lint-fix:
	ruff check --fix src tests

coverage:
	python -m pytest --cov=guardrail_compliance --cov-report=html
	@echo "Coverage report: htmlcov/index.html"

scan-example:
	guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic --no-bedrock

scan-all:
	guardrail scan examples/ --no-bedrock --policy soc2-basic --policy cis-aws-foundations --policy k8s-security

scan-k8s:
	guardrail scan examples/kubernetes/ --policy k8s-security --no-bedrock

diff-example:
	guardrail diff . --ref HEAD~1 --policy soc2-basic --no-bedrock

smoke-bedrock:
	python scripts/bedrock_smoke.py
