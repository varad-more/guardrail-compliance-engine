# Architecture

## Current pipeline

1. Parse infrastructure files into `ResourceBlock`s
2. Normalize each resource into deterministic facts + a Bedrock-friendly narrative
3. Match YAML policy rules to resource types
4. Evaluate rules locally or through Bedrock `ApplyGuardrail`
5. Emit console / JSON / SARIF / HTML output

## Important design choices

### 1. Normalization before Bedrock

Raw IaC syntax is noisy for reasoning systems. The engine builds a cleaner facts layer first.

### 2. Bedrock calls are grouped per policy/resource

The engine does **not** call Bedrock once per rule. It groups rules by policy and evaluates once per policy/resource pair.

### 3. Deterministic fallback path

The local evaluator provides a useful default path even when real Automated Reasoning policies have not been provisioned yet.
