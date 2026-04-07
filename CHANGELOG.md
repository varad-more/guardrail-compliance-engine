# Changelog

## 0.2.0 — 2026-04-06

### Added

- **Kubernetes security rules** -- 5 new rules (K8S-SEC-001–005): privileged containers, non-root enforcement, resource limits, host namespace sharing, health probes
- **Extended AWS resource coverage** -- CloudTrail logging, EBS encryption, DynamoDB encryption, VPC flow logs (4 new fact builders + checkers)
- **Auto-remediation snippets** -- FAIL findings now include copy-paste Terraform/CloudFormation/K8s fix code in console output and SARIF fixes
- **Config file auto-loading** -- `.guardrail.yaml` auto-discovered from project root; CLI args override
- **`guardrail diff` command** -- scan only files changed vs a git ref; `--format github` posts summary + inline comments to a GitHub PR
- **Inline suppression** -- `# guardrail:ignore RULE-ID` comments suppress specific rules per resource
- **Severity thresholds** -- `--severity-threshold HIGH` exits non-zero only for HIGH+ failures
- **Diff-aware scanning** -- `--changed-only REF` on the scan command limits scope to changed files

### Changed

- Replaced keyword-based rule routing (`_GENERIC_ROUTES`) with explicit `_RULE_DISPATCH` dict (31 entries)
- Replaced if/elif fact-builder dispatch with `_FACT_BUILDERS` class-level dict
- Expanded SOC 2 policy from 5 to 8 rules, CIS AWS Foundations from 5 to 8 rules
- Added `k8s-security` policy pack (5 rules)
- Test suite expanded from 26 to 82 tests

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
