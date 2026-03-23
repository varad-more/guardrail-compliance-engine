resource "aws_db_instance" "app" {
  identifier         = "guardrail-app-db"
  engine             = "postgres"
  instance_class     = "db.t3.micro"
  allocated_storage  = 20
  storage_encrypted  = true
  kms_key_id         = "arn:aws:kms:us-east-1:123456789012:key/example"
  skip_final_snapshot = true
}
