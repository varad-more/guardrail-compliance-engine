resource "aws_s3_bucket" "data_lake" {
  bucket = "guardrail-example-data-lake"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name = "guardrail-web-sg"

  ingress {
    description = "ssh from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
