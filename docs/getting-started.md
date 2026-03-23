# Getting Started

## Install

```bash
uv venv .venv
source .venv/bin/activate
uv pip install -e '.[dev]'
```

## Verify

```bash
pytest
```

## Run a scan

```bash
guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic --no-bedrock
guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic --no-bedrock --explain
```

## Generate reports

```bash
guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic --no-bedrock --format sarif --output results.sarif
guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic --no-bedrock --format html --output report.html
```
