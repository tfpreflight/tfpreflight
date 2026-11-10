provider "aws" {
  region = "us-east-1"
}

resource "aws_cloudwatch_log_stream" "s" {
  name           = "app-stream"
  log_group_name = "/example/app"
}
