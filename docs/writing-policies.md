# Writing Policies

Policies are plain YAML files.

## Shape

```yaml
name: soc2-basic
version: "0.1.0"
framework: SOC 2 Type II
rules:
  - id: SOC2-ENC-001
    title: S3 Encryption at Rest
    description: All S3 buckets must have server-side encryption enabled.
    severity: HIGH
    resource_types:
      - aws_s3_bucket
      - AWS::S3::Bucket
    constraint: S3 buckets MUST enable encryption.
    remediation: Add bucket encryption.
```

## Optional Bedrock bindings

A policy file can also include:

- `automated_reasoning_policy_arn`
- `guardrail_id`
- `guardrail_version`
- `confidence_threshold`
- `cross_region_profile`

If you attach a versioned Automated Reasoning policy ARN, `guardrail policy sync` can create or reuse a Bedrock guardrail for that policy.
