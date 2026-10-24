data "aws_caller_identity" "me" {}

resource "aws_iam_role" "sim_attacker" {
  name = "backup-operator"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = data.aws_caller_identity.me.arn }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Purpose = "attack-simulation" }
}

# Deliberately broad: a stolen credential would have whatever access it had.
# Read-only recon + the specific noisy actions our attacks need.
resource "aws_iam_role_policy" "sim_attacker" {
  name = "sim-attacker-actions"
  role = aws_iam_role.sim_attacker.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "iam:List*", "iam:Get*",
        "s3:ListAllMyBuckets", "s3:GetBucketPolicy", "s3:PutBucketPolicy",
        "s3:PutBucketPublicAccessBlock", "s3:GetObject", "s3:PutObject",
        "ec2:Describe*", "guardduty:List*", "guardduty:Get*",
        "cloudtrail:DescribeTrails", "sts:GetCallerIdentity"
      ]
      Resource = "*"
    }]
  })
}
