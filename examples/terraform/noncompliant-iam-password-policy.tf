resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length        = 8
  require_lowercase_characters  = true
  require_uppercase_characters  = false
  require_numbers               = true
  require_symbols               = false
  password_reuse_prevention     = 5
}
