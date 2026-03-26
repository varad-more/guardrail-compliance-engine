# Getting Started

## 1) Clone the repo

```bash
git clone https://github.com/varad-more/guardrail-compliance-engine.git
cd guardrail-compliance-engine
```

## 2) Install Conda if needed

### macOS

```bash
brew install --cask miniconda
conda init zsh
```

### Linux (Miniconda)

```bash
mkdir -p "$HOME/.local"
curl -fsSL "https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh" -o /tmp/miniconda.sh
bash /tmp/miniconda.sh -b -p "$HOME/.local/miniconda3"
"$HOME/.local/miniconda3/bin/conda" init bash
```

## 3) Create and activate the environment

```bash
conda env create -f environment.yml
conda activate guardrail-compliance-engine
```

If it already exists:

```bash
conda env update -f environment.yml --prune
conda activate guardrail-compliance-engine
```

## 4) Verify

```bash
pytest
guardrail --help
```

## 5) Run locally without AWS

```bash
guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic --no-bedrock
guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic --no-bedrock --explain
```

## 6) Generate reports

```bash
guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic --no-bedrock --format sarif --output results.sarif
guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic --no-bedrock --format html --output report.html
```

## 7) Install AWS CLI for live Bedrock runs

### macOS

```bash
brew install awscli
```

### Linux (AWS CLI v2)

```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
aws --version
```

## 8) Configure AWS

```bash
aws configure
export AWS_REGION=us-east-1
export AWS_DEFAULT_REGION=us-east-1
export AWS_PROFILE=your-profile
aws sts get-caller-identity
```

## 9) Approximate AWS cost expectations

Use this as a rough guide:

- local-only runs with `--no-bedrock`: **$0 AWS cost**
- AWS CLI setup and basic identity checks: **$0 to negligible**
- a few small live Bedrock smoke tests: usually **cents**, often **under $1**
- repeated Automated Reasoning build / version / export loops: can climb into **low single-digit dollars**
- heavier experimentation across many runs: keep a **$5–$20** test budget in mind

Pricing will vary with Bedrock usage, request volume, policy build iterations, region, and AWS pricing changes.

Official pricing page:

- <https://aws.amazon.com/bedrock/pricing/>

## 10) Run the live integration path

```bash
make smoke-bedrock
guardrail policy ar-list --region us-east-1
guardrail policy sync --policy-dir policies --region us-east-1
guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic --policy-dir policies --region us-east-1
```

## Final notes

- Use `--no-bedrock` for local development and CI when you do not want AWS dependency.
- Use the Bedrock path when you want real Guardrails + Automated Reasoning validation.
- If live runs fail, check credentials, region, Bedrock access, and IAM permissions before blaming the repo.
