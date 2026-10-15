resource "aws_dynamodb_table" "findings" {
  name         = "cloudsoc-findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"
  attribute {
    name = "finding_id"
    type = "S"
  }
}

data "archive_file" "triage" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/triage"
  output_path = "${path.module}/build/triage.zip"
}

resource "aws_cloudwatch_log_group" "triage" {
  name              = "/aws/lambda/cloudsoc-triage"
  retention_in_days = 14
}

resource "aws_iam_role" "triage" {
  name = "cloudsoc-triage-lambda"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "triage" {
  name = "cloudsoc-triage-least-privilege"
  role = aws_iam_role.triage.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.triage.arn}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = aws_dynamodb_table.findings.arn
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.anthropic.arn
      },
      {
        Effect   = "Allow"
        Action   = ["cloudtrail:LookupEvents"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}

resource "aws_lambda_function" "triage" {
  function_name    = "cloudsoc-triage"
  role             = aws_iam_role.triage.arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.triage.output_path
  source_code_hash = data.archive_file.triage.output_base64sha256
  timeout          = 60
  memory_size      = 256
  environment {
    variables = {
      TABLE_NAME = aws_dynamodb_table.findings.name
      SECRET_ID  = aws_secretsmanager_secret.anthropic.name
      MODEL      = "claude-sonnet-5-5"
      ALERT_TOPIC_ARN  = aws_sns_topic.alerts.arn
      ALERT_PRIORITIES = var.alert_priorities
    }
  }
  depends_on = [aws_cloudwatch_log_group.triage, aws_iam_role_policy.triage]
}
