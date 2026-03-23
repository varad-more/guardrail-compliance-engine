# Phase Status

This file tracks implementation status against the original phase plan.

## Phase 1 — Core Engine + Bedrock Integration

Status: **Done**

Implemented:
- Bedrock `ApplyGuardrail` runtime wrapper
- Automated Reasoning finding parsing (valid/invalid/satisfiable/impossible/ambiguous/tooComplex/noTranslations)
- guardrail create/list/delete support
- automated reasoning policy lifecycle support:
  - list
  - create
  - start ingest build workflow
  - build status lookup
  - create immutable version (direct hash or latest hash)
  - export policy version definition

## Phase 2 — IaC Parsers

Status: **Done**

Implemented:
- Terraform parser (`.tf` + plan JSON)
- CloudFormation parser (`.yaml/.yml/.json` with `Resources` extraction)
- Kubernetes parser (multi-document YAML)

## Phase 3 — Policy Definitions

Status: **Done**

Implemented:
- SOC2 starter rules
- HIPAA starter rules
- PCI-DSS starter rules
- CIS AWS Foundations starter rules
- custom policy schema support and validation

## Phase 4 — CLI Interface

Status: **Done**

Implemented:
- `scan`
- `audit`
- `init`
- `policy list/show/validate/sync`
- AR lifecycle commands:
  - `policy ar-list`
  - `policy ar-create`
  - `policy ar-build-status`
  - `policy ar-version`
  - `policy ar-export`

## Phase 5 — Reporting

Status: **Done**

Implemented:
- console output
- JSON output
- SARIF 2.1.0 generation
- standalone HTML report with summary donut + remediation sections

## Phase 6 — CI/CD Integration

Status: **Done**

Implemented:
- `ci.yml` test workflow
- `compliance-check.yml` workflow with SARIF upload + PR comment flow

## Phase 7 — Testing

Status: **Done**

Implemented test coverage for:
- parser behavior
- engine behavior
- normalization
- CLI behavior
- reporting output
- Bedrock client finding parsing
- policy manager operations
- additional framework evaluator reuse

Verification command:

```bash
pytest
```

## Phase 8 — Documentation

Status: **Done**

Implemented:
- README refresh
- docs pages (getting started, architecture, policy writing, CI/CD)
- phase status tracking in this file

## Post-phase hardening backlog (optional)

These are improvements beyond the original phased scope:
- richer automatic conversion from policy YAML prose into formal AR policy definitions
- deeper build-workflow asset interpretation and recommendation loops
- broader cross-file/module correlation for Terraform
