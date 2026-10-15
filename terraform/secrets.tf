resource "aws_secretsmanager_secret" "anthropic" {
  name                    = "cloudsoc/anthropic-api-key"
  description             = "Claude API key for CloudSOC triage Lambda"
  recovery_window_in_days = 0
}
