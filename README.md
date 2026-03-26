# GuardRail Compliance Engine

A compliance-as-code scanner for infrastructure definitions with an AWS Bedrock Guardrails + Automated Reasoning integration path.

This project does **not** just throw raw IaC into Bedrock and hope for divine intervention. It first parses infrastructure files, normalizes each resource into deterministic facts plus a Bedrock-friendly narrative, and then evaluates those resources locally or through Bedrock Guardrails.

## What this project does

- parses **Terraform**, **CloudFormation**, and **Kubernetes** manifests
- loads compliance rules from YAML policy packs
- normalizes resources into structured facts
- evaluates resources with:
  - deterministic local checks
  - AWS Bedrock Guardrails `ApplyGuardrail` integration
- emits **console**, **JSON**, **SARIF**, and **HTML** reports
- supports Bedrock Automated Reasoning policy lifecycle helpers for:
  - list
  - create
  - ingest build workflow start
  - build workflow status lookup
  - version creation
  - export

## Current implementation status

The planned project phases are complete.

See `PHASE_STATUS.md` for the phase tracker.

The repo currently includes:

- Terraform parser (`.tf` + plan JSON)
- CloudFormation parser
- Kubernetes multi-document YAML parser
- normalization layer for Bedrock-friendly facts
- local evaluator coverage for common AWS controls
- Bedrock `ApplyGuardrail` runtime client
- guardrail sync + Automated Reasoning lifecycle support
- CLI commands for scan / audit / policy operations
- CI workflows
- automated tests

## Why the normalization layer exists

Automated Reasoning is much more useful when it reasons over **clear facts** instead of noisy HCL/YAML syntax.

So the engine converts resources into a narrative like:

- bucket encryption configured: true/false
- logging target bucket: value or none
- matching public access block present: true/false
- public SSH exposure: true/false
- RDS encryption + KMS posture

That gives you:

- deterministic local checks right now
- explainable scans
- a cleaner path for Bedrock evaluation later

## Inference flow

The engine evaluates infrastructure in two layers:

1. **Parse** raw IaC into resource objects.
2. **Normalize** those resources into deterministic facts plus a Bedrock-friendly narrative.
3. **Infer locally** using built-in compliance evaluators for common controls.
4. **Infer with Bedrock** when enabled by sending normalized content through Bedrock Guardrails and linked Automated Reasoning policies.
5. **Merge findings** into a single report format.

That split matters because it keeps the core scan explainable even when Bedrock is unavailable, and it makes the final result easier to audit than dumping raw HCL/YAML into a model-shaped void.

---

## Installation

### 1) Clone the repo

```bash
git clone https://github.com/varad-more/guardrail-compliance-engine.git
cd guardrail-compliance-engine
```

### 2) Install Conda if you do not already have it

#### macOS

```bash
brew install --cask miniconda
conda init zsh
```

#### Linux (Miniconda)

```bash
mkdir -p "$HOME/.local"
curl -fsSL "https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh" -o /tmp/miniconda.sh
bash /tmp/miniconda.sh -b -p "$HOME/.local/miniconda3"
"$HOME/.local/miniconda3/bin/conda" init bash
```

Restart your shell after `conda init`, or source your shell rc file.

### 3) Create and activate the Conda environment

```bash
conda env create -f environment.yml
conda activate guardrail-compliance-engine
```

If the environment already exists, update it with:

```bash
conda env update -f environment.yml --prune
conda activate guardrail-compliance-engine
```

### 4) Verify the install

```bash
pytest
guardrail --help
```

---

## Fast local testing

Assume the Conda environment is already active:

```bash
conda activate guardrail-compliance-engine
```

If you want to test the project **without AWS hookup**, use the bundled examples.

### Run unit/integration tests

```bash
pytest
```

### Scan Terraform locally

```bash
guardrail scan examples/terraform/noncompliant-s3.tf \
  --policy soc2-basic \
  --no-bedrock
```

### Explain mode

This prints the normalized facts/narrative used by the engine.

```bash
guardrail scan examples/terraform/noncompliant-s3.tf \
  --policy soc2-basic \
  --no-bedrock \
  --explain
```

### CloudFormation example

```bash
guardrail scan examples/cloudformation/noncompliant-stack.yaml \
  --policy soc2-basic \
  --no-bedrock
```

### Audit by framework shortcut

```bash
guardrail audit examples/cloudformation/noncompliant-stack.yaml \
  --frameworks soc2 \
  --no-bedrock \
  --format json
```

### Generate SARIF

```bash
guardrail scan examples/terraform/noncompliant-s3.tf \
  --policy soc2-basic \
  --no-bedrock \
  --format sarif \
  --output results.sarif
```

### Generate HTML report

```bash
guardrail scan examples/terraform/noncompliant-s3.tf \
  --policy soc2-basic \
  --no-bedrock \
  --format html \
  --output report.html
```

---

## AWS hookup guide

If you want **real Bedrock-backed validation**, you need an AWS environment with Bedrock Guardrails + Automated Reasoning available.

### Recommended region

Use:

- `us-east-1`

### Install AWS CLI

If you do not already have the AWS CLI, install it before trying live Bedrock commands.

#### macOS

```bash
brew install awscli
```

#### Linux (AWS CLI v2)

```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
aws --version
```

### Prerequisites

You need:

- an AWS account with Bedrock access enabled
- Bedrock Guardrails access
- Automated Reasoning access
- credentials available to the process, for example via:
  - `AWS_PROFILE`
  - standard AWS CLI config
  - environment variables
  - an attached IAM role

### Minimal environment setup

Configure AWS credentials first:

```bash
aws configure
```

Then set the region used by the repo:

```bash
export AWS_REGION=us-east-1
export AWS_DEFAULT_REGION=us-east-1
export AWS_PROFILE=your-profile
```

Optional sanity checks:

```bash
aws --version
aws sts get-caller-identity
aws bedrock list-guardrails --region us-east-1
```

### Approximate AWS cost expectations

Use this as a **rough testing budget**, not a pricing contract.

- **Local mode (`--no-bedrock`)**: effectively **$0 AWS cost**. Parsing, normalization, local evaluation, and report generation stay on your machine.
- **AWS CLI install / `aws configure` / basic identity checks**: effectively **$0 to negligible**.
- **Small live smoke test with existing Bedrock setup**: usually **cents**, and typically **under $1** for a couple of small example runs.
- **Creating / iterating on Automated Reasoning policies**: can move from **cents into low single-digit dollars** if you repeat builds, versioning, exports, and live scans a few times.
- **Heavier experimentation** (many runs, larger source documents, repeated policy rebuilds): budget **around $5–$20** so you do not get surprised.

What drives cost the most:

- how many live Bedrock requests you make
- size of the infrastructure input / normalized content
- number of Automated Reasoning build iterations
- region and current Amazon Bedrock pricing

Safest rule: do local work first with `--no-bedrock`, then switch to live Bedrock only for final validation.

For current pricing, check the official Amazon Bedrock pricing page:

- <https://aws.amazon.com/bedrock/pricing/>

### IAM permissions

At minimum, your runtime needs Bedrock access for:

- `bedrock:ApplyGuardrail`
- `bedrock:CreateGuardrail`
- `bedrock:UpdateGuardrail`
- `bedrock:GetGuardrail`
- `bedrock:ListGuardrails`
- `bedrock:DeleteGuardrail`
- `bedrock:CreateGuardrailVersion`
- `bedrock:CreateAutomatedReasoningPolicy`
- `bedrock:GetAutomatedReasoningPolicy`
- `bedrock:ListAutomatedReasoningPolicies`
- `bedrock:StartAutomatedReasoningPolicyBuildWorkflow`
- `bedrock:GetAutomatedReasoningPolicyBuildWorkflow`
- `bedrock:CreateAutomatedReasoningPolicyVersion`
- `bedrock:ExportAutomatedReasoningPolicyVersion`

Example IAM policy:

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

---

## Bedrock hookup flow

There are two practical ways to use the project.

### Mode 1: local evaluator only

Good for:

- development
- CI without live AWS
- testing parser/report behavior

Use `--no-bedrock`.

### Mode 2: Bedrock-backed evaluation

Good for:

- real Guardrails validation
- testing Automated Reasoning policy lifecycle
- proving the live AWS integration path

### Step 1: list existing AR policies

```bash
guardrail policy ar-list --region us-east-1
```

### Step 2: create an Automated Reasoning policy draft

```bash
guardrail policy ar-create \
  --name "infra-compliance" \
  --description "Infrastructure compliance reasoning policy" \
  --source-file ./policy-source.txt \
  --region us-east-1
```

That command creates the policy and optionally starts an ingest build workflow from a `.txt` or `.pdf` source file.

### Step 3: check build status

```bash
guardrail policy ar-build-status \
  --policy-arn <policy-arn> \
  --workflow-id <workflow-id> \
  --region us-east-1
```

### Step 4: create an immutable policy version

```bash
guardrail policy ar-version \
  --policy-arn <policy-arn> \
  --region us-east-1
```

### Step 5: export the built policy definition

```bash
guardrail policy ar-export \
  --policy-version-arn <policy-arn>:1 \
  --output policy-definition.json \
  --region us-east-1
```

### Step 6: bind a versioned AR policy ARN in a YAML policy file

Example:

```yaml
name: soc2-basic
version: "0.1.0"
framework: SOC 2 Type II
automated_reasoning_policy_arn: arn:aws:bedrock:us-east-1:123456789012:automated-reasoning-policy/infra-compliance:1
confidence_threshold: 0.8
cross_region_profile: us.guardrail.v1:0
rules:
  ...
```

### Step 7: sync YAML policies to Bedrock guardrails

```bash
guardrail policy sync --policy-dir policies --region us-east-1
```

That creates or reuses Bedrock guardrails for YAML policies that include a versioned `automated_reasoning_policy_arn`.

### Step 8: run a live Bedrock scan

Once the YAML policy has a Bedrock guardrail binding or an AR policy ARN that gets synced into a guardrail, run scans **without** `--no-bedrock`:

```bash
guardrail scan examples/terraform/noncompliant-s3.tf \
  --policy soc2-basic \
  --policy-dir policies \
  --region us-east-1
```

---

## Running the repo

### Local-only run (no AWS required)

```bash
guardrail scan examples/terraform/noncompliant-s3.tf \
  --policy soc2-basic \
  --no-bedrock
```

### Local explain run

```bash
guardrail scan examples/terraform/noncompliant-s3.tf \
  --policy soc2-basic \
  --no-bedrock \
  --explain
```

### Live Bedrock smoke run

This checks whether your local AWS setup can talk to Bedrock for the integration path:

```bash
make smoke-bedrock
```

### Live policy + scan flow

```bash
guardrail policy ar-list --region us-east-1
guardrail policy sync --policy-dir policies --region us-east-1
guardrail scan examples/terraform/noncompliant-s3.tf \
  --policy soc2-basic \
  --policy-dir policies \
  --region us-east-1
```

## CLI quick reference

```bash
# Scan
guardrail scan <file-or-dir> --policy soc2-basic --no-bedrock
guardrail scan <file-or-dir> --policy soc2-basic --format json
guardrail scan <file-or-dir> --policy soc2-basic --format sarif --output results.sarif
guardrail scan <file-or-dir> --policy soc2-basic --format html --output report.html

# Audit
guardrail audit <file-or-dir> --frameworks soc2,hipaa --no-bedrock

# Policies
guardrail policy list
guardrail policy show soc2-basic
guardrail policy validate policies/custom-example.yaml
guardrail policy sync --policy-dir policies

# Automated Reasoning lifecycle
guardrail policy ar-list
guardrail policy ar-create --name "infra-compliance" --source-file ./policy-source.txt
guardrail policy ar-build-status --policy-arn <policy-arn> --workflow-id <workflow-id>
guardrail policy ar-version --policy-arn <policy-arn>
guardrail policy ar-export --policy-version-arn <policy-arn>:1 --output policy-definition.json
```

---

## Resource coverage today

### Deterministic evaluator coverage

- S3 encryption
- S3 access logging
- S3 public access posture
- RDS encryption + KMS presence
- security group public ingress / SSH exposure
- IAM password policy strength

### Parsed resource coverage

- Terraform:
  - `aws_s3_bucket`
  - `aws_s3_bucket_public_access_block`
  - `aws_db_instance`
  - `aws_security_group`
  - `aws_iam_account_password_policy`
  - plan JSON resource records
- CloudFormation:
  - `AWS::S3::Bucket`
  - `AWS::EC2::SecurityGroup`
  - generic `Resources` extraction
- Kubernetes:
  - multi-document YAML parsing
  - `Pod`, `Deployment`, `Service`, and other manifest kinds as parsed resources

---

## Reporting

- **console**: human-readable tree output
- **json**: machine-readable structured output
- **sarif**: GitHub Security tab compatible findings
- **html**: standalone executive report with inline styling and SVG score donut

---

## Testing matrix

### What is verified locally

- parser behavior
- engine behavior
- normalization layer
- CLI behavior
- reporting output
- Bedrock client finding parsing
- policy manager operations
- framework evaluator reuse

Run everything:

```bash
pytest
```

### What still depends on real AWS hookup

These need a live Bedrock-enabled AWS environment to fully validate end to end:

- actual `ApplyGuardrail` requests against your guardrail
- AR policy build workflows against Bedrock
- guardrail creation against your account
- live region/account permission verification

---

## CI/CD

The repo includes:

- `ci.yml` for install + tests
- `compliance-check.yml` for SARIF-producing compliance scans on pull requests

The compliance workflow currently defaults to `--no-bedrock` so it works in CI without requiring live Bedrock provisioning.

---

## Known limitations

- not every policy rule has a unique bespoke deterministic evaluator yet; some framework packs reuse generic evaluator routing
- Kubernetes is parsed and normalized, but AWS-focused policy packs remain the primary rule coverage
- cross-file Terraform/module correlation can still be improved
- real-world Automated Reasoning policy authoring quality still depends on the source material you provide to Bedrock

---

## Project status

For the planned scope, coding is complete and the repo test suite is green.

If you want to keep pushing it, the highest-value follow-ups are:

1. deeper live AWS validation against your Bedrock environment
2. better Terraform cross-file/module correlation
3. richer PR summary/comment generation
4. stronger policy-authoring UX for Automated Reasoning source material

---

## Final notes

- **Local mode is first-class**: you can parse, normalize, evaluate, and generate reports without touching AWS.
- **Bedrock mode is the real integration proof**: use it when you want live Guardrails and Automated Reasoning validation, not just deterministic checks.
- **AWS CLI setup matters**: most live run failures are not code bugs; they are usually missing credentials, missing region config, missing Bedrock access, or missing IAM permissions.
- **Recommended release gate**: before tagging, run local tests, build artifacts, and at least one successful live Bedrock smoke/integration pass in a real AWS account.
