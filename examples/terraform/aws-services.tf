# Noncompliant AWS resources for testing extended resource coverage.

resource "aws_cloudtrail" "bad" {
  name                       = "bad-trail"
  s3_bucket_name             = "my-trail-bucket"
  is_multi_region_trail      = false
  enable_log_file_validation = false
}

resource "aws_cloudtrail" "good" {
  name                       = "good-trail"
  s3_bucket_name             = "my-trail-bucket"
  is_multi_region_trail      = true
  enable_log_file_validation = true
}

resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = false
}

resource "aws_ebs_volume" "encrypted" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = true
  kms_key_id        = "arn:aws:kms:us-east-1:123456789012:key/abcd-1234"
}

resource "aws_dynamodb_table" "no_sse" {
  name         = "bad-table"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
}

resource "aws_dynamodb_table" "with_sse" {
  name         = "good-table"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  server_side_encryption {
    enabled = true
  }
}

resource "aws_flow_log" "no_destination" {
  vpc_id       = "vpc-abc123"
  traffic_type = "ALL"
}

resource "aws_flow_log" "with_destination" {
  vpc_id          = "vpc-abc123"
  traffic_type    = "ALL"
  log_destination = "arn:aws:s3:::my-flow-logs"
}
