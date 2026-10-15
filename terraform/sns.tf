variable "alert_email" {
  type = string
}

variable "alert_priorities" {
  type    = string
  default = "P1,P2"
}

resource "aws_sns_topic" "alerts" {
  name = "cloudsoc-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
