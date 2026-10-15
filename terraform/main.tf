terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.0" }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = "cloudsoc", ManagedBy = "terraform" }
  }
}

variable "region" {
  default = "us-east-2"
}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  trail_name = "cloudsoc-trail"
}
