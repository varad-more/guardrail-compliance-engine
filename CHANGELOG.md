# Changelog

## 0.1.0 — 2026-03-25

Initial public release.

### Features

- **Multi-format IaC parsing** -- Terraform (`.tf` + plan JSON), CloudFormation (YAML/JSON), Kubernetes multi-document YAML
- **Resource normalisation** -- raw properties converted to structured facts and a Bedrock-friendly plain-text narrative
- **Deterministic local checks** -- S3 encryption/logging/public access, RDS encryption, security group ingress, IAM password policy
- **AWS Bedrock Guardrails integration** -- send normalised resources to `ApplyGuardrail` for Automated Reasoning validation
- **Four output formats** -- console tree (Rich), JSON, SARIF (GitHub Security tab), standalone HTML report with donut chart
- **YAML policy packs** -- declarative rules with severity, resource type targeting, constraints, and remediation
- **Automated Reasoning lifecycle CLI** -- `ar-create`, `ar-build-status`, `ar-version`, `ar-export` commands
- **Starter policy packs** -- SOC 2, CIS AWS Foundations, PCI-DSS, HIPAA, and a custom example
- **CI-ready** -- GitHub Actions workflows for tests and SARIF-producing compliance scans on PRs
