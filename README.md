# GuardRail Compliance Engine

A compliance-as-code scanner for infrastructure definitions with a Bedrock Guardrails + Automated Reasoning integration path.

This project treats Bedrock Guardrails as a **runtime reasoning layer**, but it does not blindly throw raw IaC at Bedrock and pray. It first parses infrastructure files and normalizes each resource into deterministic facts and a Bedrock-friendly narrative.

## Current status

This repo is no longer just a scaffold. The current implementation includes:

- Terraform parser
- CloudFormation parser
- Kubernetes parser
- YAML policy registry
- deterministic normalization layer
- local rule evaluators for high-value AWS controls
- Bedrock `ApplyGuardrail` client wrapper
- Bedrock guardrail sync/management scaffold
- console / JSON / SARIF / HTML reporting
- CI workflow + SARIF upload workflow
- CLI commands for scan, audit, init, and policy management
- automated tests

## Why normalization exists

Bedrock Automated Reasoning is much more useful when it evaluates clear facts instead of raw HCL or giant YAML blobs.

So the engine converts resources into a structured narrative such as:

- bucket encryption configured: true/false
- logging target bucket: value or none
- matching public access block present: true/false
- public SSH exposure: true/false
- RDS encryption + KMS posture

That gives you:

- deterministic local checks right now
- a cleaner Bedrock evaluation path later
- explainable scans instead of mystery verdicts

## Quick start

```bash
uv venv .venv
source .venv/bin/activate
uv pip install -e '.[dev]'
pytest

guardrail policy list
guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic --no-bedrock
guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic --no-bedrock --explain
guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic --no-bedrock --format sarif --output results.sarif
guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic --no-bedrock --format html --output report.html
```

## CLI examples

> Full phase tracker: see `PHASE_STATUS.md`.

```bash
# Scan a single file
guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic --no-bedrock

# Scan a directory
guardrail scan examples/ --policy soc2-basic --no-bedrock

# Explain mode: show normalized facts + narrative
guardrail scan examples/cloudformation/noncompliant-stack.yaml --policy soc2-basic --no-bedrock --explain

# Audit by framework shortcut
guardrail audit examples/cloudformation/noncompliant-stack.yaml --frameworks soc2 --no-bedrock --format json

# Validate a policy file
guardrail policy validate policies/custom-example.yaml

# Sync policies that have Automated Reasoning policy ARNs attached
guardrail policy sync --policy-dir policies

# Automated Reasoning lifecycle helpers
guardrail policy ar-list
guardrail policy ar-create --name "infra-compliance" --source-file ./policy-source.txt
guardrail policy ar-build-status --policy-arn <policy-arn> --workflow-id <workflow-id>
guardrail policy ar-version --policy-arn <policy-arn>
guardrail policy ar-export --policy-version-arn <policy-arn>:1 --output policy-definition.json
```

## Supported resource coverage today

### Local evaluators implemented

- S3 encryption
- S3 access logging
- S3 public access posture
- RDS encryption + KMS presence
- security group public ingress / SSH exposure

### Resource types parsed today

- Terraform:
  - `aws_s3_bucket`
  - `aws_s3_bucket_public_access_block`
  - `aws_db_instance`
  - `aws_security_group`
  - plan JSON resource records
- CloudFormation:
  - `AWS::S3::Bucket`
  - `AWS::EC2::SecurityGroup`
  - generic `Resources` extraction
- Kubernetes:
  - multi-document YAML parsing
  - `Pod`, `Deployment`, `Service`, and other manifest kinds as parsed resources

## Reporting

- **console**: human-readable tree output
- **json**: machine-readable structured output
- **sarif**: GitHub Security tab compatible findings
- **html**: standalone executive report with inline styling and SVG score donut

## Bedrock integration notes

The Bedrock path is wired for the current API shape:

- `ApplyGuardrail` runtime calls
- `outputScope="FULL"`
- versioned Automated Reasoning policy ARNs attached to guardrails
- required cross-region guardrail profile support in guardrail creation

The repo also parses richer Automated Reasoning finding structures such as:

- valid / invalid / satisfiable / impossible
- translation ambiguity
- supporting or contradicting rules
- translation confidence
- scenario traces

## Current limitations

- not all policy rules have deterministic local evaluators yet
- real Automated Reasoning policy creation/versioning is still a partially scaffolded flow
- cross-file Terraform correlation can be improved further
- Kubernetes policies are parsed and normalized, but the AWS-focused starter rule packs are still the main rule coverage

## Test status

The repo includes coverage for:

- parsers
- engine behavior
- normalization
- reporting
- CLI commands
- Bedrock runtime finding parsing
- guardrail manager behavior

Run everything with:

```bash
pytest
```

## Next high-value build items

1. real Automated Reasoning policy lifecycle support
2. stronger cross-file / module correlation for Terraform
3. broader deterministic evaluator coverage for HIPAA / PCI / CIS rule packs
4. richer PR summary/comment generation in CI
