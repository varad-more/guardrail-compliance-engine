# GuardRail Compliance Engine

Terraform-first compliance scanning with a Bedrock Guardrails + Automated Reasoning integration path.

## What this repo is right now

This is an MVP scaffold focused on the parts that matter first:
- Terraform parsing
- policy registry + YAML rules
- a deterministic normalization layer that turns resources into Bedrock-friendly facts + narratives
- local fallback checks for a few high-value SOC 2 rules
- CLI + console / JSON reporting

The Bedrock side is wired for the real API shape:
- `ApplyGuardrail` at runtime
- versioned Automated Reasoning policy ARNs attached to guardrails
- cross-region guardrail config when creating guardrails

## Quick start

```bash
uv venv .venv
source .venv/bin/activate
uv pip install -e '.[dev]'

guardrail policy list
guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic --no-bedrock
guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic --no-bedrock --explain
```

## Current MVP scope

- Terraform `.tf` parsing
- SOC 2 starter policy set
- normalized facts per resource
- local deterministic evaluation for a few rules
- Bedrock runtime client + guardrail manager scaffolding
- test coverage for parser, engine, CLI, normalization, and Bedrock call grouping behavior

## Implementation notes

### Why normalization exists

Automated Reasoning is better at validating clear facts than raw IaC syntax blobs.
The engine now builds a normalized narrative per resource before any Bedrock evaluation path.

Examples of normalized facts:
- S3 bucket encryption configured
- S3 logging target bucket
- matching public access block presence
- RDS encryption + KMS posture
- security group public ingress ports / SSH exposure

### Current limitation

The Bedrock integration path is structurally correct, but the repo still uses local deterministic checks as the default practical evaluator until real Automated Reasoning policies and guardrail bindings are provisioned.

## Next planned steps

1. Real Bedrock-backed policy sync and guardrail binding flow
2. SARIF output
3. CloudFormation + Kubernetes parsers
4. richer CI / PR workflow
5. stronger cross-resource correlation across Terraform files and modules
