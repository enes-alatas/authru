# Parameter Store Resources

# Example Parameter Store parameter for API credentials
resource "aws_ssm_parameter" "example_api_token" {
  count = var.create_example_parameter ? 1 : 0

  name        = "/authru/tokens/example-api"
  description = "Example API credentials for Authru (update with real values)"
  type        = "SecureString"
  value       = "username:password"

  tags = merge(local.common_tags, {
    Name = "authru-example-token"
  })

  lifecycle {
    ignore_changes = [value] # Don't overwrite if manually updated
  }
}
