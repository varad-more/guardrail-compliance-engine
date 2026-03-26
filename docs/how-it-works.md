# How GuardRail Compliance Engine Works

## The Pipeline

```
IaC File (.tf / .yaml / .json)
  |
  v
+-----------+    Regex + hcl2 library extract each resource block
|  Parser   |    with its type, name, properties, and line number
+-----+-----+
      |  List[ResourceBlock]
      v
+--------------+    Converts raw properties into structured facts:
|  Normalizer  |    "encryption_configured: False", "ssh_open_to_world: True"
|              |    Also builds a plain-English narrative for Bedrock
+-----+--------+
      |  NormalizedResource (facts dict + text string)
      v
+--------------+    Loads YAML policy packs, matches rules to
|   Policy     |    the resource type (e.g. aws_s3_bucket matches
|   Registry   |    SOC2-ENC-001, SOC2-LOG-001, SOC2-NET-001)
+-----+--------+
      |  List[(PolicyDefinition, PolicyRule)]
      v
+--------------+
|   Engine     |---- Does this policy have a guardrail_id?
|              |         |
|              |    NO   |   YES
|              |    v    |    v
|              |  Local  |  Bedrock
|              |  Check  |  ApplyGuardrail
+-----+--------+
      |  List[Finding] (PASS / FAIL / WARN with proof)
      v
+--------------+
|  Reporter    |---> Console tree / JSON / SARIF / HTML
+--------------+
```

---

## Step by Step: What Happens When You Run a Scan

### Step 1: Parser Reads the File

```bash
guardrail scan examples/terraform/noncompliant-s3.tf --policy soc2-basic --no-bedrock
```

The `TerraformParser` reads the `.tf` file, uses a regex to find `resource "aws_s3_bucket" "data_lake" {`, extracts the block, parses properties (`acl = "public-read"`, `bucket = "..."`), and returns a `ResourceBlock`:

```python
ResourceBlock(
    resource_type="aws_s3_bucket",
    resource_name="data_lake",
    properties={"acl": "public-read", "bucket": "guardrail-example-data-lake"},
    line_number=1,
)
```

Each parser handles its own format:

| Parser | What it does |
|--------|-------------|
| `TerraformParser` | Regex finds `resource` blocks, hcl2 library parses properties (falls back to heuristic line-by-line parsing). Also handles plan JSON. |
| `CloudFormationParser` | Loads YAML/JSON, checks for `Resources` section, extracts each logical resource with its `Type` and `Properties`. |
| `KubernetesParser` | Splits multi-document YAML on `---`, extracts each document with a `kind` field as a resource. |

The engine auto-detects which parser to use based on file extension and content.

---

### Step 2: Normalizer Extracts Facts

The normalizer takes each `ResourceBlock` and builds two things:

1. **A facts dictionary** -- structured, queryable data for local checks
2. **A text narrative** -- plain English for Bedrock Automated Reasoning

For the S3 bucket, the normalizer checks the properties:

| Property checked | Value found | Fact produced |
|-----------------|-------------|---------------|
| `server_side_encryption_configuration` block? | Missing | `encryption_configured: False` |
| `logging` block? | Missing | `logging_configured: False` |
| `acl` value? | `public-read` | `acl: public-read` |
| Matching `aws_s3_bucket_public_access_block` in file? | None found | `public_access_block_present: False` |

The text narrative looks like:

```
Resource type: aws_s3_bucket
Resource name: data_lake
Declared at line: 1
Bucket name: guardrail-example-data-lake
Acl: public-read
Encryption configured: False
Logging configured: False
Logging target bucket: None
Public access block present: False
Public access block resources: []
Public access block all enabled: False
Properties:
acl: public-read
bucket: guardrail-example-data-lake
```

The normalizer has dedicated fact extractors for each resource type:

| Resource type | Facts extracted |
|--------------|----------------|
| `aws_s3_bucket` / `AWS::S3::Bucket` | Encryption, logging, ACL, public access block linkage |
| `aws_s3_bucket_public_access_block` | All four block flags, bucket reference |
| `aws_db_instance` / `AWS::RDS::DBInstance` | Storage encryption, KMS key, public accessibility |
| `aws_security_group` / `AWS::EC2::SecurityGroup` | Ingress rules, public ports, SSH exposure |
| `Pod` / `Deployment` | runAsNonRoot, privileged, service account |

For Terraform vs CloudFormation, it handles the naming differences (e.g. `storage_encrypted` vs `StorageEncrypted`).

---

### Step 3: Policy Registry Matches Rules

The registry loads the YAML policy file (`soc2-basic.yaml`) and finds rules whose `resource_types` list includes the current resource type.

For `aws_s3_bucket`, three rules match:

| Rule ID | Title | Severity |
|---------|-------|----------|
| SOC2-ENC-001 | S3 Encryption at Rest | HIGH |
| SOC2-LOG-001 | S3 Access Logging | MEDIUM |
| SOC2-NET-001 | No Public S3 Buckets | CRITICAL |

Rules are grouped by policy so all rules from the same policy go to the same evaluator (local or Bedrock).

---

### Step 4a: Local Evaluation (`--no-bedrock`)

The engine dispatches each rule to a checker method. Dispatch works in two tiers:

**Tier 1 -- Exact rule-ID lookup.** A `_RULE_DISPATCH` dictionary maps known rule IDs directly to checker methods:

```python
_RULE_DISPATCH = {
    "SOC2-ENC-001": "_check_s3_encryption",
    "SOC2-LOG-001": "_check_s3_logging",
    "SOC2-NET-001": "_check_s3_public_access",
    "SOC2-ENC-002": "_check_rds_encryption",
    "SOC2-NET-002": "_check_security_group_ingress",
}
```

**Tier 2 -- Keyword fallback.** If the rule ID isn't in the dict, a `_GENERIC_ROUTES` table matches by resource type + keywords in the rule text. For example, a CIS rule with "encrypt" in its description hitting an `aws_s3_bucket` resource gets routed to `_check_s3_encryption`.

Each checker reads the normalized facts and returns a Finding:

| Rule | Fact checked | Value | Result |
|------|-------------|-------|--------|
| SOC2-ENC-001 | `encryption_configured` | `False` | **FAIL** -- "No server_side_encryption_configuration block found" |
| SOC2-LOG-001 | `logging_configured` | `False` | **FAIL** -- "Bucket logging block is missing" |
| SOC2-NET-001 | `acl` | `public-read` | **FAIL** -- "Bucket ACL is explicitly public: public-read" |

Rules with no matching checker return a `WARN` with "No local evaluator implemented yet".

---

### Step 4b: Bedrock Evaluation (`--bedrock`)

When the policy YAML has a `guardrail_id`, the engine skips local checks and sends the normalized text narrative to AWS Bedrock:

```
ApplyGuardrail(
    guardrailIdentifier="your-guardrail-id",
    guardrailVersion="1",
    source="OUTPUT",
    content=[{text: "Resource type: aws_s3_bucket\nEncryption configured: False\n..."}]
)
```

Bedrock's Automated Reasoning engine then:

1. Receives the normalized text
2. Attempts to translate statements into formal logic claims
3. Checks those claims against the rules it built from the policy source document
4. Returns findings with a type indicating the reasoning result

| Finding type | Meaning | Engine maps to |
|-------------|---------|----------------|
| `valid` | Claims are logically supported by the policy | PASS |
| `invalid` | Claims contradict the policy rules | FAIL |
| `impossible` | Translated premises are logically impossible | FAIL |
| `satisfiable` | Claims could be true or false depending on missing info | WARN |
| `translationAmbiguous` | Multiple logical interpretations possible | WARN |
| `noTranslations` | Couldn't translate input into policy-relevant logic | WARN |
| `tooComplex` | Input too complex for formal reasoning | WARN |

Each finding includes:
- **Translation confidence** -- how confident the engine is in its logical translation
- **Premises and claims** -- the formal logic it derived
- **Supporting/contradicting rules** -- which policy rules apply
- **Scenarios** -- claims-true and claims-false scenarios showing what would need to be true

The `BedrockGuardrailClient` parses all of this into the same `Finding` dataclass used by local checks.

---

### Step 5: Reporter Outputs Results

All findings are collected into a `ScanResult` per file, containing `ResourceEvaluation` entries per resource. The reporter renders them:

**Console** (`--format console`, default):
```
examples/terraform/noncompliant-s3.tf (TerraformParser)
+-- aws_s3_bucket.data_lake
|   +-- FAIL  SOC2-ENC-001  S3 Encryption at Rest
|   +-- FAIL  SOC2-LOG-001  S3 Access Logging
|   +-- FAIL  SOC2-NET-001  No Public S3 Buckets
+-- aws_security_group.web
    +-- FAIL  SOC2-NET-002  No Unrestricted Security Group Ingress

Files scanned: 1 | Passed: 0 | Failed: 4 | Warnings: 0
```

**JSON** (`--format json`): Full structured output including normalized facts, proofs, and raw Bedrock payloads.

**SARIF** (`--format sarif`): GitHub Security tab compatible. Each finding becomes a SARIF result with rule descriptors, physical file locations, and severity mapping.

**HTML** (`--format html`): Standalone file with embedded CSS, SVG donut chart showing compliance score, collapsible resource sections, and print-friendly styling.

---

## The Bedrock Lifecycle

Setting up Bedrock Automated Reasoning is a one-time process per policy:

```
policy-source.txt (natural language compliance rules)
  |
  v
guardrail policy ar-create              Creates an AR policy in Bedrock.
  |                                     Uploads the source document.
  |                                     Starts an ingest build workflow.
  v
guardrail policy ar-build-status        Bedrock converts the natural language
  |                                     into formal logic rules. Takes 1-5 min.
  |                                     Poll until status = COMPLETED.
  v
guardrail policy ar-version             Creates an immutable version (v1).
  |                                     Required before binding to a guardrail.
  v
Edit policies/soc2-basic.yaml           Add two fields:
  |                                       automated_reasoning_policy_arn: <arn>:1
  |                                       guardrail_id: (added by sync)
  v
guardrail policy sync                   Creates a Bedrock guardrail resource
  |                                     that wraps the versioned AR policy.
  |                                     Returns and stores the guardrail_id.
  v
guardrail scan (without --no-bedrock)   Engine detects guardrail_id on the
                                        policy, sends normalized text to
                                        ApplyGuardrail instead of running
                                        local checks.
```

The `policy-source.txt` is the key input. It should describe compliance rules in clear natural language with RFC 2119 keywords (MUST, MUST NOT, SHOULD). The better the source document matches the patterns in your normalized text, the more claims Bedrock can translate and reason over.

---

## File Reference

### Core

| File | Role |
|------|------|
| `cli.py` | Typer CLI entry point. Defines `scan`, `audit`, `init`, and all `policy` subcommands. Parses args, creates `EngineConfig`, calls the engine, routes output to a reporter. |
| `core/engine.py` | Orchestrator. For each resource: normalize, match policy rules, evaluate (local dispatch or Bedrock), collect findings into `ScanResult`. |
| `core/normalization.py` | Converts raw `ResourceBlock` properties into structured facts dict and plain-text narrative. Has dedicated extractors per resource type. |
| `core/guardrail_client.py` | Async wrapper around the `ApplyGuardrail` Bedrock Runtime API. Parses assessment responses into `Finding` objects with proofs. |
| `core/policy_manager.py` | Manages Bedrock guardrail CRUD and AR policy lifecycle: create, ingest build, version, export. |
| `core/models.py` | Dataclasses: `Finding`, `ComplianceResult`, `ResourceEvaluation`, `ScanResult`, `GuardrailInfo`, `AutomatedReasoningPolicyInfo`. |

### Parsers

| File | Role |
|------|------|
| `parsers/base.py` | `IaCParser` abstract base class and `ResourceBlock` dataclass. |
| `parsers/terraform.py` | Parses `.tf` files (regex + hcl2 with heuristic fallback) and Terraform plan JSON. |
| `parsers/cloudformation.py` | Parses CloudFormation YAML/JSON templates. Detects by `Resources` key. |
| `parsers/kubernetes.py` | Parses multi-document Kubernetes YAML. Detects by `kind` field. |

### Policies

| File | Role |
|------|------|
| `policies/registry.py` | Loads YAML policy files into `PolicyDefinition` objects. Validates structure. Matches rules to resource types. Lazy-loads on first access. |
| `policies/*.yaml` | Declarative policy packs. Each rule has: id, title, severity, resource_types, constraint, remediation. |

### Reporting

| File | Role |
|------|------|
| `reporting/console.py` | Rich library tree output with color-coded status and summary panel. |
| `reporting/json_report.py` | Recursive dataclass-to-dict converter for JSON serialization. |
| `reporting/sarif.py` | SARIF 2.1.0 format with rule descriptors, physical locations, and severity mapping. |
| `reporting/html_report.py` | Standalone HTML with embedded CSS, SVG donut chart, collapsible sections. |

### Utils

| File | Role |
|------|------|
| `utils/config.py` | `EngineConfig` dataclass: region, policy dir, selected policies, output format, bedrock toggle. |
| `utils/exceptions.py` | Exception hierarchy: `GuardrailComplianceError` > `ParserError`, `PolicyValidationError`, `BedrockEvaluationError`. |
