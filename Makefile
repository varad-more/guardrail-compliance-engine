PYTHON ?= python3

install:
	$(PYTHON) -m pip install -e '.[dev]'

test:
	pytest

scan-example:
	guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic
