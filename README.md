# GuardRail Compliance Engine

Scan Terraform, CloudFormation, and Kubernetes files for compliance violations — locally in seconds, or using AWS Bedrock Guardrails for Automated Reasoning validation.

**New to the project? Start here:** [Quick Start](#quick-start) → [First Scan](#first-scan) → [Understanding Results](#understanding-results)

---

## What it does

GuardRail parses your infrastructure files, normalizes each resource into structured facts, then checks those facts against policy rules. You can run it entirely offline (no AWS needed) or connect it to Bedrock Guardrails for AI-powered Automated Reasoning.

```
IaC file → Parse → Normalize → Evaluate → Report
```

Results come out as a **color-coded console tree**, **JSON**, **SARIF** (GitHub Security tab), or a **standalone HTML report** with charts.

---

## Features

- **Three IaC formats** — Terraform (`.tf` + plan JSON), CloudFormation (YAML/JSON), Kubernetes manifests
- **Local deterministic checks** — no AWS needed; runs offline in CI for S3, RDS, security groups, and IAM password policy
- **Bedrock Guardrails integration** — send normalized resources to `ApplyGuardrail` for Automated Reasoning
- **Retry + timeout** — Bedrock calls retry up to 3× with exponential back-off; configurable per-call timeout
- **Secret redaction** — detects AWS keys, private keys, passwords, and tokens in IaC before they reach Bedrock
- **Visual HTML report** — compliance score donut, severity bar chart, top failing rules leaderboard, per-file table
- **Rich console dashboard** — per-file summary table, severity chart, and top rules panel alongside the tree output
- **Declarative YAML policies** — add rules without touching Python; built-in packs for SOC 2, CIS AWS, PCI-DSS, HIPAA
- **Full AR lifecycle CLI** — create, build, version, and export Automated Reasoning policies from the terminal
- **CI-ready** — GitHub Actions workflows for tests, coverage, linting, and SARIF uploads

---

## Quick Start

**Requirements:** Python 3.11+, no AWS account needed for local scanning.

### 1. Install

```bash
# With pip
pip install -e '.[dev]'

# Or with uv (faster)
uv venv .venv && source .venv/bin/activate
uv pip install -e '.[dev]'
```

### 2. Verify

```bash
pytest           # all 26 tests should pass
guardrail --help # explore available commands
```

### 3. First scan

```bash
guardrail scan examples/terraform/noncompliant-s3.tf \
  --policy soc2-basic \
  --no-bedrock
```

No AWS credentials needed with `--no-bedrock`.

---

## Understanding Results

### Console output

Each file is rendered as a tree. Each resource shows its findings inline.

```
examples/terraform/noncompliant-s3.tf (TerraformParser)
├── aws_s3_bucket.data_lake
│   ├── FAIL  SOC2-ENC-001  S3 Encryption at Rest — No encryption configuration found.
│   ├── FAIL  SOC2-LOG-001  S3 Access Logging — Bucket logging is missing.
│   └── FAIL  SOC2-NET-001  No Public S3 Buckets — Bucket ACL is explicitly public: public-read.
└── aws_security_group.web
    └── FAIL  SOC2-NET-002  No Unrestricted Security Group Ingress — SSH is open to the internet.
```

Below the tree, three dashboard panels are printed:

| Panel | Contents |
|---|---|
| **Summary** | Overall score, total files, pass/fail/warn counts |
| **Severity** | Unicode bar chart of failures by severity (CRITICAL → LOW) |
| **Top Rules** | Bar chart of the 5 most-failing rule IDs |

A **Files** table then shows per-file scores at a glance.

### HTML report

```bash
guardrail scan examples/ --policy soc2-basic --no-bedrock \
  --format html --output report.html
open report.html
```

The HTML report contains:

- **Compliance score donut** — color-coded green/yellow/red based on pass rate
- **Severity bar chart** — horizontal bars for CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL failures
- **Top failing rules leaderboard** — the 5 rules that fail most often with relative bar lengths
- **Files table** — per-file pass/fail/warn counts and score
- **Findings detail** — expandable sections for each resource with normalized facts and proof text

Everything is self-contained (no CDN, no external scripts).

### Finding statuses

| Status | Meaning |
|---|---|
| `PASS` | Rule is satisfied |
| `FAIL` | Rule is violated; remediation guidance is shown |
| `WARN` | Indeterminate — check manually or wire to Bedrock |

---

## Usage

### Scanning

```bash
# Single file
guardrail scan main.tf --policy soc2-basic --no-bedrock

# Directory (recursive by default)
guardrail scan infra/ --policy soc2-basic --policy cis-aws-foundations --no-bedrock

# Non-recursive
guardrail scan infra/ --policy soc2-basic --no-bedrock --no-recursive

# Fail CI on any finding (exit code 1)
guardrail scan infra/ --policy soc2-basic --no-bedrock --fail-on-findings
```

### Auditing by framework

Match policies by framework name instead of the exact policy name:

```bash
guardrail audit infra/ --frameworks soc2 --no-bedrock
guardrail audit infra/ --frameworks soc2,hipaa --no-bedrock --format json
```

### Output formats

| Format | Flag | Use case |
|---|---|---|
| `console` | `--format console` | Human-readable tree + dashboard (default) |
| `json` | `--format json` | Machine-readable; pipe to `jq` |
| `sarif` | `--format sarif` | GitHub Security tab and code scanning |
| `html` | `--format html` | Standalone report with charts |

Write to a file with `--output`:

```bash
guardrail scan infra/ --policy soc2-basic --no-bedrock --format sarif --output results.sarif
guardrail scan infra/ --policy soc2-basic --no-bedrock --format html  --output report.html
```

### Explain mode

Print the normalized facts the engine produces for each resource — useful for debugging policies:

```bash
guardrail scan main.tf --policy soc2-basic --no-bedrock --explain
```

### Logging

Set `--log-level` to see internal engine activity on stderr:

```bash
# Show scan progress and Bedrock retry events
guardrail scan infra/ --policy soc2-basic --log-level INFO

# Full debug output (parser decisions, normalized text, every Bedrock attempt)
guardrail scan infra/ --policy soc2-basic --log-level DEBUG
```

Levels: `DEBUG`, `INFO`, `WARNING` (default), `ERROR`

### CI integration

The repo includes two GitHub Actions workflows:

**`ci.yml`** — runs on every push and PR:
- Installs dependencies (with pip cache)
- Runs `ruff check` for linting
- Runs `pytest` with coverage (80%+ required)

**`compliance-check.yml`** — runs on PRs touching `.tf`, `.yaml`, `.yml`, `.json`:
- Produces a SARIF report and uploads it to the GitHub Security tab
- Posts a PR comment listing critical/high findings on failure
- Optionally uses Bedrock if `AWS_ROLE_ARN` is set

---

## Policy System

### Built-in policies

| Policy | Framework | Rules |
|---|---|---|
| `soc2-basic` | SOC 2 Type II | 5 |
| `cis-aws-foundations` | CIS AWS Foundations | 5 |
| `pci-dss-basic` | PCI DSS | 5 |
| `hipaa-basic` | HIPAA | 5 |
| `custom-example` | Custom | 1 |

```bash
guardrail policy list               # list all
guardrail policy show soc2-basic    # view rules
```

### Writing custom policies

Create a YAML file in your policies directory:

```yaml
name: my-org-policy
version: "1.0.0"
framework: Internal
description: Organization-specific compliance rules.
rules:
  - id: ORG-S3-001
    title: S3 buckets must be encrypted
    description: All S3 buckets require server-side encryption.
    severity: HIGH
    resource_types:
      - aws_s3_bucket
      - AWS::S3::Bucket
    constraint: S3 bucket configurations MUST include server-side encryption.
    remediation: Add a server_side_encryption_configuration block with AES256 or aws:kms.
```

**Required rule fields:** `id`, `title`, `severity`, `resource_types`, `constraint`

**Optional:** `description`, `remediation`

Validate before using:

```bash
guardrail policy validate my-org-policy.yaml
```

Point the engine at your custom directory:

```bash
guardrail scan infra/ --policy my-org-policy --policy-dir ./my-policies --no-bedrock
```

### Policy commands

```bash
guardrail policy list                              # list all available policies
guardrail policy show soc2-basic                   # display rules in a policy
guardrail policy validate policies/my-policy.yaml  # validate YAML structure
guardrail policy sync --policy-dir policies        # sync to Bedrock guardrails
```

---

## AWS Bedrock Integration

### Evaluation modes

| Mode | Flag | Requires AWS | Use case |
|---|---|---|---|
| **Local only** | `--no-bedrock` | No | Dev, CI, offline scanning |
| **Bedrock** | `--bedrock` | Yes | Automated Reasoning validation |

### Prerequisites

1. An AWS account with Bedrock and Automated Reasoning access in `us-east-1`
2. Credentials via `AWS_PROFILE`, environment variables, or an IAM role
3. IAM permissions (see below)

```bash
export AWS_REGION=us-east-1
export AWS_PROFILE=your-profile

# Verify access
aws sts get-caller-identity
aws bedrock list-guardrails --region us-east-1

# Smoke test
python scripts/bedrock_smoke.py
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

### Automated Reasoning lifecycle

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

# 5. Export the policy definition as JSON
guardrail policy ar-export \
  --policy-version-arn <policy-arn>:1 \
  --output policy-definition.json
```

### Live Bedrock scanning

Bind a versioned AR policy in your YAML policy file:

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

Sync to create the Bedrock guardrail, then scan:

```bash
guardrail policy sync --policy-dir policies
guardrail scan infra/ --policy soc2-basic --region us-east-1
```

---

## Docker

Build and run the engine in a container (non-root user, no AWS credentials baked in):

```bash
docker build -t guardrail .

# Local scan (mount your IaC directory)
docker run --rm -v $(pwd)/infra:/infra guardrail \
  scan /infra --policy soc2-basic --no-bedrock

# With AWS credentials for Bedrock
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_REGION=us-east-1 \
  -v $(pwd)/infra:/infra \
  guardrail scan /infra --policy soc2-basic
```

---

## Architecture

```
src/guardrail_compliance/
  cli.py                  # Typer CLI — scan, audit, policy commands
  core/
    engine.py             # Orchestrator: parse → normalize → evaluate
    normalization.py      # Extracts deterministic facts + narrative text
    guardrail_client.py   # Async Bedrock wrapper with retry + timeout
    policy_manager.py     # Bedrock guardrail and AR policy lifecycle
    models.py             # Finding, ScanResult, ResourceEvaluation, etc.
  parsers/
    base.py               # IaCParser ABC and ResourceBlock
    terraform.py          # .tf files (hcl2 + heuristic fallback) and plan JSON
    cloudformation.py     # YAML/JSON with a Resources section
    kubernetes.py         # Multi-document YAML manifests
  policies/
    registry.py           # YAML loading, validation, and rule matching
  reporting/
    console.py            # Rich tree + dashboard (summary, severity, top rules)
    json_report.py        # JSON serialization
    sarif.py              # SARIF 2.1.0 format
    html_report.py        # Self-contained HTML with SVG charts
  utils/
    config.py             # EngineConfig dataclass
    exceptions.py         # GuardrailComplianceError hierarchy
    logging_config.py     # setup_logging() — package-scoped, stderr
    secrets.py            # redact_secrets() — AWS keys, tokens, passwords
```

**Why normalize first?**

Rather than sending raw HCL or YAML to Bedrock, the engine extracts structured facts (`encryption_configured`, `ssh_open_to_world`, etc.) and builds a clean narrative. This gives fast deterministic local checks for free and produces far better Automated Reasoning results.

---

## Resource Coverage

### Deterministic checks (no AWS needed)

| Check | Resource types |
|---|---|
| S3 encryption at rest | `aws_s3_bucket`, `AWS::S3::Bucket` |
| S3 access logging | `aws_s3_bucket`, `AWS::S3::Bucket` |
| S3 public access posture | `aws_s3_bucket`, `aws_s3_bucket_public_access_block` |
| RDS encryption with KMS | `aws_db_instance`, `AWS::RDS::DBInstance` |
| Security group ingress | `aws_security_group`, `AWS::EC2::SecurityGroup` |
| IAM password policy | `aws_iam_account_password_policy` |

### Parser coverage

| Parser | File types | Notes |
|---|---|---|
| Terraform | `.tf`, plan JSON | hcl2 library with heuristic fallback |
| CloudFormation | `.yaml`, `.yml`, `.json` | Detects `Resources` section |
| Kubernetes | `.yaml`, `.yml` | Multi-document, detects `kind` field |

---

## Development

### Setup

```bash
git clone https://github.com/varad-more/guardrail-compliance-engine.git
cd guardrail-compliance-engine
pip install -e '.[dev]'
```

### Common tasks

```bash
make test        # run tests with coverage (80% minimum)
make lint        # ruff check — must pass before merging
make lint-fix    # auto-fix ruff issues
make coverage    # run tests and open HTML coverage report
make scan-example  # quick local scan of the bundled example files
make smoke-bedrock # verify AWS credentials and Bedrock access
```

### Adding a new check

1. Add the rule to a YAML policy file under `policies/`
2. Add a `_check_*` method to `engine.py`
3. Register it in `_RULE_DISPATCH` (by exact rule ID) or `_GENERIC_ROUTES` (by keyword)
4. Extend `normalization.py` if the check needs new facts
5. Add a test

### Adding a new parser

1. Create a class extending `IaCParser` in `parsers/`
2. Implement `supports()` and `parse()` returning `ResourceBlock` instances
3. Add it to `self.parsers` in `ComplianceEngine.__init__`
4. Add normalization support in `ResourceNormalizer._build_facts` if needed

---

## Known Limitations

- Not every rule has a dedicated local evaluator — some fall back to keyword routing
- Kubernetes manifests are parsed but the built-in policy packs focus on AWS resources
- Cross-file Terraform module correlation is basic
- Automated Reasoning quality depends on the source material provided to Bedrock

---

## License

[MIT](LICENSE)
