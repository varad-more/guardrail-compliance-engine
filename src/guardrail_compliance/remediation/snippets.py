"""Remediation snippet registry.

Each entry maps a checker name to resource-type-specific Terraform/CloudFormation
code snippets that show users exactly how to fix a FAIL finding.
"""
from __future__ import annotations

# checker_name -> resource_type -> snippet string
_SNIPPETS: dict[str, dict[str, str]] = {
    "_check_s3_encryption": {
        "aws_s3_bucket": """\
resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}""",
        "AWS::S3::Bucket": """\
BucketEncryption:
  ServerSideEncryptionConfiguration:
    - ServerSideEncryptionByDefault:
        SSEAlgorithm: aws:kms""",
    },
    "_check_s3_logging": {
        "aws_s3_bucket": """\
resource "aws_s3_bucket_logging" "example" {
  bucket        = aws_s3_bucket.example.id
  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "log/"
}""",
        "AWS::S3::Bucket": """\
LoggingConfiguration:
  DestinationBucketName: !Ref LogBucket
  LogFilePrefix: log/""",
    },
    "_check_s3_public_access": {
        "aws_s3_bucket_public_access_block": """\
resource "aws_s3_bucket_public_access_block" "example" {
  bucket                  = aws_s3_bucket.example.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}""",
        "aws_s3_bucket": """\
resource "aws_s3_bucket_public_access_block" "example" {
  bucket                  = aws_s3_bucket.example.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}""",
        "AWS::S3::Bucket": """\
PublicAccessBlockConfiguration:
  BlockPublicAcls: true
  BlockPublicPolicy: true
  IgnorePublicAcls: true
  RestrictPublicBuckets: true""",
    },
    "_check_rds_encryption": {
        "aws_db_instance": """\
resource "aws_db_instance" "example" {
  # ... existing config ...
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
}""",
        "AWS::RDS::DBInstance": """\
StorageEncrypted: true
KmsKeyId: !Ref RdsKmsKey""",
    },
    "_check_rds_backup": {
        "aws_db_instance": """\
resource "aws_db_instance" "example" {
  # ... existing config ...
  backup_retention_period = 7
}""",
    },
    "_check_security_group_ingress": {
        "aws_security_group": """\
ingress {
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
# Remove or restrict SSH ingress:
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]  # internal only
}""",
        "AWS::EC2::SecurityGroup": """\
SecurityGroupIngress:
  - IpProtocol: tcp
    FromPort: 443
    ToPort: 443
    CidrIp: 0.0.0.0/0
  - IpProtocol: tcp
    FromPort: 22
    ToPort: 22
    CidrIp: 10.0.0.0/8  # internal only""",
    },
    "_check_password_policy": {
        "aws_iam_account_password_policy": """\
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_uppercase_characters   = true
  require_lowercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  password_reuse_prevention      = 24
  max_password_age               = 90
  allow_users_to_change_password = true
}""",
    },
    "_check_cloudtrail_logging": {
        "aws_cloudtrail": """\
resource "aws_cloudtrail" "main" {
  name                          = "main-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  enable_logging                = true
}""",
        "AWS::CloudTrail::Trail": """\
IsLogging: true
IsMultiRegionTrail: true
EnableLogFileValidation: true
S3BucketName: !Ref TrailBucket""",
    },
    "_check_ebs_encryption": {
        "aws_ebs_volume": """\
resource "aws_ebs_volume" "example" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = true
  kms_key_id        = aws_kms_key.ebs.arn
}""",
        "AWS::EC2::Volume": """\
Encrypted: true
KmsKeyId: !Ref EbsKmsKey""",
    },
    "_check_dynamodb_encryption": {
        "aws_dynamodb_table": """\
server_side_encryption {
  enabled     = true
  kms_key_arn = aws_kms_key.dynamo.arn
}""",
        "AWS::DynamoDB::Table": """\
SSESpecification:
  SSEEnabled: true
  KMSMasterKeyId: !Ref DynamoKmsKey""",
    },
    "_check_vpc_flow_logs": {
        "aws_flow_log": """\
resource "aws_flow_log" "example" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  log_destination = aws_s3_bucket.flow_logs.arn
}""",
        "AWS::EC2::FlowLog": """\
ResourceId: !Ref VPC
TrafficType: ALL
LogDestination: !GetAtt FlowLogBucket.Arn""",
    },
    "_check_k8s_privileged": {
        "*": """\
securityContext:
  privileged: false""",
    },
    "_check_k8s_run_as_root": {
        "*": """\
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000""",
    },
    "_check_k8s_resource_limits": {
        "*": """\
resources:
  limits:
    cpu: "500m"
    memory: "128Mi"
  requests:
    cpu: "250m"
    memory: "64Mi\"""",
    },
    "_check_k8s_host_namespaces": {
        "*": """\
spec:
  hostNetwork: false
  hostPID: false
  hostIPC: false""",
    },
    "_check_k8s_probes": {
        "*": """\
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 15
readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10""",
    },
}


def get_snippet(checker_name: str, resource_type: str) -> str | None:
    """Return a remediation snippet for the given checker and resource type, or None."""
    by_type = _SNIPPETS.get(checker_name)
    if not by_type:
        return None
    return by_type.get(resource_type) or by_type.get("*")
