# Getting Started

```bash
uv venv .venv
source .venv/bin/activate
uv pip install -e '.[dev]'
pytest

guardrail policy list
guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic --no-bedrock
guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic --no-bedrock --explain
```
