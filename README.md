# GuardRail Compliance Engine

A compliance scanner for Terraform, CloudFormation, and Kubernetes that can run locally or connect to AWS Bedrock Guardrails for Automated Reasoning validation.

It parses your infrastructure files, normalizes each resource into structured facts and a plain text narrative, then checks them against policy rules. It ships with starter policy packs for SOC 2, CIS AWS Foundations, PCI DSS, and HIPAA and can output results as a console tree, JSON, SARIF, or a standalone HTML report.

### Console output

<!-- Replace with a terminal screenshot for the colored version: -->
<!-- ![Console scan output](docs/assets/console-output.png) -->

```bash
guardrail scan examples/ --policy soc2-basic --no-bedrock
```

```
examples/cloudformation/compliant-stack.yaml (CloudFormationParser)
└── AWS::S3::Bucket.LogsBucket
    ├── PASS  SOC2-ENC-001  S3 Encryption at Rest
    ├── PASS  SOC2-LOG-001  S3 Access Logging
    └── PASS  SOC2-NET-001  No Public S3 Buckets

examples/cloudformation/noncompliant-stack.yaml (CloudFormationParser)
├── AWS::S3::Bucket.PublicBucket
│   ├── FAIL  SOC2-ENC-001  S3 Encryption at Rest — No encryption configuration found.
│   ├── FAIL  SOC2-LOG-001  S3 Access Logging — Bucket logging is missing.
│   └── FAIL  SOC2-NET-001  No Public S3 Buckets — Bucket ACL is explicitly public: publicread.
└── AWS::EC2::SecurityGroup.WebSecurityGroup
    └── FAIL  SOC2-NET-002  No Unrestricted Security Group Ingress — SSH is open to the internet.

examples/terraform/compliant-s3.tf (TerraformParser)
├── aws_s3_bucket.logs
│   ├── PASS  SOC2-ENC-001  S3 Encryption at Rest
│   ├── PASS  SOC2-LOG-001  S3 Access Logging
│   └── PASS  SOC2-NET-001  No Public S3 Buckets
└── aws_s3_bucket_public_access_block.logs
    └── PASS  SOC2-NET-001  No Public S3 Buckets

examples/terraform/noncompliant-s3.tf (TerraformParser)
├── aws_s3_bucket.data_lake
│   ├── FAIL  SOC2-ENC-001  S3 Encryption at Rest — No encryption configuration found.
│   ├── FAIL  SOC2-LOG-001  S3 Access Logging — Bucket logging is missing.
│   └── FAIL  SOC2-NET-001  No Public S3 Buckets — Bucket ACL is explicitly public: public-read.
└── aws_security_group.web
    └── FAIL  SOC2-NET-002  No Unrestricted Security Group Ingress — SSH is open to the internet.

Files scanned: 10 | Passed: 8 | Failed: 9 | Warnings: 0
```

### HTML report

You can also generate a standalone HTML report with a visual compliance score:

```bash
guardrail scan examples/ --policy soc2-basic --no-bedrock --format html --output report.html
```

<!-- Replace with a screenshot of the HTML report: -->
<!-- ![HTML compliance report](docs/assets/html-report.png) -->

The HTML report includes a donut chart, per file breakdowns, finding details with remediation guidance, and works on its own without any external dependencies.

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Scanning](#scanning)
  - [Auditing by Framework](#auditing-by-framework)
  - [Output Formats](#output-formats)
  - [Explain Mode](#explain-mode)
  - [CI Integration](#ci-integration)
- [Policy System](#policy-system)
  - [Built in Policies](#built-in-policies)
  - [Writing Custom Policies](#writing-custom-policies)
  - [Policy Commands](#policy-commands)
- [AWS Bedrock Integration](#aws-bedrock-integration)
  - [Prerequisites](#prerequisites)
  - [Automated Reasoning Lifecycle](#automated-reasoning-lifecycle)
  - [Live Bedrock Scanning](#live-bedrock-scanning)
- [Architecture](#architecture)
- [Resource Coverage](#resource-coverage)
- [Development](#development)
- [License](#license)

---

## Features

- **Parses multiple formats.** Terraform (`.tf` and plan JSON), CloudFormation (YAML and JSON), and Kubernetes manifests with multiple documents.
- **Normalizes before evaluating.** Raw IaC properties get converted into structured facts like encryption status, logging config, and public exposure before any checks run.
- **Deterministic local checks.** S3 encryption, logging, and public access. RDS encryption with KMS. Security group ingress rules. IAM password policy strength.
- **Bedrock Guardrails integration.** Send normalized resources to the `ApplyGuardrail` API for Automated Reasoning validation when you need more than deterministic checks.
- **Four output formats.** Console tree for humans, JSON for scripts, SARIF for the GitHub Security tab, and a standalone HTML report with a compliance score.
- **Declarative YAML policies.** Define rules with severity levels, resource type targeting, constraints, and remediation guidance. No code changes needed to add new rules.
- **Full AR policy lifecycle.** CLI commands to create, build, version, and export Automated Reasoning policies directly from the terminal.
- **Ready for CI.** Includes GitHub Actions workflows for running tests and producing SARIF compliance scans on pull requests.

---

## Quick Start

**Requirements:** Python 3.11 or newer.

### Install with pip

```bash
pip install -e '.[dev]'
```

### Install with uv

```bash
uv venv .venv && source .venv/bin/activate
uv pip install -e '.[dev]'
```

### Verify

```bash
pytest                    # run tests
guardrail --help          # check CLI
```

### First scan

```bash
guardrail scan examples/terraform/noncompliant-s3.tf \
  --policy soc2-basic \
  --no-bedrock
```

No AWS credentials needed when running in local only mode.

---

## Usage

### Scanning

Scan a single file or an entire directory:

```bash
# Single file
guardrail scan main.tf --policy soc2-basic --no-bedrock

# Directory (recursive by default)
guardrail scan infra/ --policy soc2-basic --policy cis-aws-foundations --no-bedrock

# Non recursive
guardrail scan infra/ --policy soc2-basic --no-bedrock --no-recursive
```

You can make the process exit with a non zero code on failures, which is useful for CI gates:

```bash
guardrail scan infra/ --policy soc2-basic --no-bedrock --fail-on-findings
```

### Auditing by Framework

Match policies by framework name instead of the exact policy name:

```bash
guardrail audit infra/ --frameworks soc2 --no-bedrock
guardrail audit infra/ --frameworks soc2,hipaa --no-bedrock --format json
```

### Output Formats

| Format    | Flag              | Use case                                |
|-----------|-------------------|-----------------------------------------|
| `console` | `--format console` | Human readable tree (default)          |
| `json`    | `--format json`   | Machine readable, pipe to `jq`          |
| `sarif`   | `--format sarif`  | GitHub Security tab and code scanning   |
| `html`    | `--format html`   | Standalone report with compliance score |

Write output to a file with `--output`:

```bash
guardrail scan infra/ --policy soc2-basic --no-bedrock \
  --format sarif --output results.sarif

guardrail scan infra/ --policy soc2-basic --no-bedrock \
  --format html --output report.html
```

### Explain Mode

Print the normalized facts and narrative the engine produces for each resource:

```bash
guardrail scan examples/terraform/noncompliant-s3.tf \
  --policy soc2-basic --no-bedrock --explain
```

This is useful for debugging policies and understanding exactly what the engine sees before it runs checks.

### CI Integration

The repo includes two GitHub Actions workflows:

**`ci.yml`** runs tests on every push and pull request.

**`compliance-check.yml`** runs a SARIF producing compliance scan on pull requests that touch `.tf`, `.yaml`, `.yml`, or `.json` files. It uploads findings to the GitHub Security tab and posts a pull request comment on failure.

To use Bedrock backed scanning in CI, set the `AWS_ROLE_ARN` secret to an IAM role with Bedrock permissions. Without it, scans run in local only mode.

---

## Policy System

### Built in Policies

| Policy               | Framework            | Rules |
|----------------------|----------------------|-------|
| `soc2-basic`         | SOC 2 Type II        | 5     |
| `cis-aws-foundations` | CIS AWS Foundations  | 5     |
| `pci-dss-basic`      | PCI DSS              | 5     |
| `hipaa-basic`        | HIPAA                | 5     |
| `custom-example`     | Custom               | 1     |

List all available policies:

```bash
guardrail policy list
```

### Writing Custom Policies

Create a YAML file in your policies directory:

```yaml
name: my-org-policy
version: "1.0.0"
framework: Internal
description: Organization specific compliance rules.
rules:
  - id: ORG-S3-001
    title: S3 buckets must be encrypted
    description: All S3 buckets require server side encryption.
    severity: HIGH
    resource_types:
      - aws_s3_bucket
      - AWS::S3::Bucket
    constraint: S3 bucket configurations MUST include server side encryption.
    remediation: Add a server_side_encryption_configuration block with AES256 or aws:kms.
```

**Required fields per rule:** `id`, `title`, `severity`, `resource_types`, `constraint`

**Optional fields:** `description`, `remediation`

Validate before using:

```bash
guardrail policy validate my-org-policy.yaml
```

### Policy Commands

```bash
guardrail policy list                              # list all policies
guardrail policy show soc2-basic                   # show rules in a policy
guardrail policy validate policies/my-policy.yaml  # validate YAML structure
guardrail policy sync --policy-dir policies        # sync to Bedrock guardrails
```

---

## AWS Bedrock Integration

The engine supports two evaluation modes:

| Mode            | Flag            | Requires AWS | Use case                        |
|-----------------|-----------------|--------------|----------------------------------|
| **Local only**  | `--no-bedrock`  | No           | Dev, CI, offline scanning        |
| **Bedrock**     | `--bedrock`     | Yes          | Automated Reasoning validation   |

### Prerequisites

For Bedrock backed scanning you need:

1. An AWS account with Bedrock and Automated Reasoning access in `us-east-1`
2. Credentials available via `AWS_PROFILE`, environment variables, or an IAM role
3. IAM permissions for the Bedrock actions listed below

```bash
export AWS_REGION=us-east-1
export AWS_PROFILE=your-profile

# Verify access
aws sts get-caller-identity
aws bedrock list-guardrails --region us-east-1
```

<details>
<summary>Required IAM permissions</summary>

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:ApplyGuardrail",
        "bedrock:CreateGuardrail",
        "bedrock:UpdateGuardrail",
        "bedrock:GetGuardrail",
        "bedrock:ListGuardrails",
        "bedrock:DeleteGuardrail",
        "bedrock:CreateGuardrailVersion",
        "bedrock:CreateAutomatedReasoningPolicy",
        "bedrock:GetAutomatedReasoningPolicy",
        "bedrock:ListAutomatedReasoningPolicies",
        "bedrock:StartAutomatedReasoningPolicyBuildWorkflow",
        "bedrock:GetAutomatedReasoningPolicyBuildWorkflow",
        "bedrock:CreateAutomatedReasoningPolicyVersion",
        "bedrock:ExportAutomatedReasoningPolicyVersion"
      ],
      "Resource": "*"
    }
  ]
}
```

</details>

### Automated Reasoning Lifecycle

The CLI provides commands for the full AR policy lifecycle:

```bash
# 1. List existing AR policies
guardrail policy ar-list

# 2. Create a policy and start an ingest build from a source document
guardrail policy ar-create \
  --name "infra-compliance" \
  --description "Infrastructure compliance reasoning policy" \
  --source-file ./policy-source.txt

# 3. Check build status
guardrail policy ar-build-status \
  --policy-arn <policy-arn> \
  --workflow-id <workflow-id>

# 4. Create an immutable version
guardrail policy ar-version --policy-arn <policy-arn>

# 5. Export the policy definition
guardrail policy ar-export \
  --policy-version-arn <policy-arn>:1 \
  --output policy-definition.json
```

### Live Bedrock Scanning

Once you have a versioned AR policy, bind it in your YAML policy file:

```yaml
name: soc2-basic
version: "0.1.0"
framework: SOC 2 Type II
automated_reasoning_policy_arn: arn:aws:bedrock:us-east-1:123456789012:automated-reasoning-policy/infra-compliance:1
confidence_threshold: 0.8
cross_region_profile: us.guardrail.v1:0
rules:
  # ...
```

Sync the policy to create a Bedrock guardrail, then scan without the `--no-bedrock` flag:

```bash
guardrail policy sync --policy-dir policies
guardrail scan infra/ --policy soc2-basic --region us-east-1
```

---

## Architecture

```
src/guardrail_compliance/
  cli.py                  # Typer CLI with scan, audit, and policy commands
  core/
    engine.py             # Orchestrator: parse, normalize, evaluate
    normalization.py      # Turns resources into deterministic facts and narrative
    guardrail_client.py   # Async Bedrock ApplyGuardrail wrapper
    policy_manager.py     # Bedrock guardrail and AR policy lifecycle
    models.py             # Dataclasses for Finding, ScanResult, etc.
  parsers/
    base.py               # IaCParser base class and ResourceBlock
    terraform.py          # .tf files (hcl2 with heuristic fallback) and plan JSON
    cloudformation.py     # YAML and JSON with a Resources section
    kubernetes.py         # Multi document YAML manifests
  policies/
    registry.py           # YAML policy loading, validation, and matching
  reporting/
    console.py            # Rich tree output
    json_report.py        # JSON serialization
    sarif.py              # SARIF 2.1.0 format
    html_report.py        # Standalone HTML with SVG donut chart
  utils/
    config.py             # EngineConfig dataclass
    exceptions.py         # Error hierarchy
```

**Data flow:**

```
IaC file -> Parser -> ResourceBlock -> Normalizer -> NormalizedResource
  -> Engine (local checks or Bedrock) -> Findings -> Reporter
```

The normalization layer is the key design decision. Rather than sending raw HCL or YAML to Bedrock, the engine first extracts structured facts (encryption status, ACL value, logging target, and so on) and builds a clean narrative. This gives deterministic local checks for free and produces much better Automated Reasoning results.

---

## Resource Coverage

### Deterministic Checks

| Check                      | Resource Types                                        |
|----------------------------|-------------------------------------------------------|
| S3 encryption at rest      | `aws_s3_bucket`, `AWS::S3::Bucket`                    |
| S3 access logging          | `aws_s3_bucket`, `AWS::S3::Bucket`                    |
| S3 public access posture   | `aws_s3_bucket`, `aws_s3_bucket_public_access_block`  |
| RDS encryption with KMS    | `aws_db_instance`, `AWS::RDS::DBInstance`             |
| Security group ingress     | `aws_security_group`, `AWS::EC2::SecurityGroup`       |
| IAM password policy        | `aws_iam_account_password_policy`                     |

### Parser Coverage

| Parser         | File Types              | Notes                                 |
|----------------|-------------------------|---------------------------------------|
| Terraform      | `.tf`, plan JSON        | hcl2 library with heuristic fallback  |
| CloudFormation | `.yaml`, `.yml`, `.json`| Detects the Resources section         |
| Kubernetes     | `.yaml`, `.yml`         | Multi document, detects the kind field|

Rules that don't have a specific local evaluator fall through to keyword based generic routing. Any rule can be wired to Bedrock for Automated Reasoning evaluation by binding an AR policy in the YAML.

---

## Development

### Setup

```bash
git clone https://github.com/varad-more/guardrail-compliance-engine.git
cd guardrail-compliance-engine
pip install -e '.[dev]'
```

### Run Tests

```bash
pytest             # all tests
pytest -q          # quiet mode
pytest -x          # stop on first failure
```

### Project Structure

```
tests/                     # pytest suite
examples/
  terraform/               # compliant and noncompliant .tf files
  cloudformation/          # compliant and noncompliant stacks
  kubernetes/              # compliant and noncompliant manifests
policies/                  # YAML policy packs
scripts/                   # utility scripts (Bedrock smoke test)
.github/workflows/         # CI and compliance check workflows
```

### Adding a New Check

1. Add the rule to a YAML policy file under `policies/`
2. Add a `_check_*` method to `engine.py`
3. Register it in `_RULE_DISPATCH` (by rule ID) or `_GENERIC_ROUTES` (by keyword)
4. If the check needs new facts, extend `normalization.py`
5. Add a test

### Adding a New Parser

1. Create a class extending `IaCParser` in `parsers/`
2. Implement `supports()` and `parse()` returning `ResourceBlock` instances
3. Add it to the parser list in `ComplianceEngine.__init__`
4. Add normalization support in `ResourceNormalizer._build_facts` if needed

---

## Known Limitations

- Not every policy rule has a dedicated local evaluator. Some use keyword based generic routing.
- Kubernetes manifests are parsed and normalized, but the built in policy packs focus on AWS resources.
- Cross file Terraform module correlation is basic.
- Automated Reasoning quality depends on the source material you provide to Bedrock.

---

## License

[MIT](LICENSE)
