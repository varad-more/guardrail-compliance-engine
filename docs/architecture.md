# Architecture

Current MVP path:

1. Terraform parser extracts `ResourceBlock`s
2. normalization layer converts each resource into deterministic facts + a Bedrock-friendly narrative
3. policy registry matches YAML rules to resource types
4. engine evaluates rules locally or via Bedrock `ApplyGuardrail`
5. reporting renders console / JSON output

Important implementation detail: Bedrock evaluation is grouped **once per policy per resource**, not once per rule, to avoid duplicate `ApplyGuardrail` calls.
