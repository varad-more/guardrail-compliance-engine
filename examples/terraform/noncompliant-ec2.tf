resource "aws_security_group" "bad_admin" {
  name = "bad-admin-sg"

  ingress {
    description = "admin from internet"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
