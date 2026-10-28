variable "aws_region" {
  description = "Region to deploy to."
  type        = string
}

variable "aws_profile" {
  description = "Name of the AWS CLI profile Terraform uses."
  type        = string
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile

  # Plan without calling AWS.
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
}

resource "aws_s3_bucket" "logs" {
  bucket = "acme-logs"
}

resource "aws_sns_topic" "alerts" {
  name = "acme-alerts"
}
