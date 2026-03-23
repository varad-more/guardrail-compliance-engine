# GuardRail Compliance Engine

Terraform-first compliance scanning with a Bedrock Guardrails + Automated Reasoning integration path.

## What this repo is right now

This is an MVP scaffold focused on the parts that matter first:
- Terraform parsing
- policy registry + YAML rules
- normalized resource facts for Bedrock evaluation
- local fallback checks for a few high-value SOC 2 rules
- CLI + console / JSON reporting

The Bedrock side is wired for the real API shape:
- `ApplyGuardrail` at runtime
- versioned Automated Reasoning policy ARNs attached to guardrails
- cross-region guardrail config when creating guardrails

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

guardrail policy list
guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic
```

## Current MVP scope

- Terraform `.tf` parsing
- SOC 2 starter policy set
- local heuristic evaluation for a few rules
- Bedrock runtime client + guardrail manager scaffolding

## Next planned steps

1. Bedrock-backed policy sync flow
2. SARIF output
3. CloudFormation + Kubernetes parsers
4. richer CI workflow
