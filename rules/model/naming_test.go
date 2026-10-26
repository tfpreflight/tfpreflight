package model

import "testing"

func TestResourceNamesReadAsProse(t *testing.T) {
	for resourceType, want := range map[string]string{
		"aws_iam_role":                     "an IAM role",
		"aws_s3_bucket":                    "an S3 bucket",
		"aws_s3_bucket_cors_configuration": "an S3 bucket CORS configuration",
		"aws_instance":                     "an instance",
		"aws_vpc":                          "a VPC",
		"aws_db_instance":                  "a DB instance",
		"aws_eip":                          "an Elastic IP",
		"aws_ec2_transit_gateway":          "an EC2 transit gateway",
		"aws_kms_key":                      "a KMS key",
		"aws_cloudwatch_log_group":         "a CloudWatch log group",
		"aws_elasticache_cluster":          "an ElastiCache cluster",
		"aws_lambda_function":              "a Lambda function",
		"aws_lb":                           "a load balancer",
		"aws_route53_zone":                 "a Route 53 zone",
		"aws_sqs_queue":                    "an SQS queue",
		"aws_nat_gateway":                  "a NAT gateway",
		"aws_iam_user":                     "an IAM user",
		"aws_default_route_table":          "a default route table",
		"aws_opensearch_domain":            "an OpenSearch domain",
		"aws_iam_saml_provider":            "an IAM SAML provider",
		"aws_wafv2_web_acl":                "a WAFv2 web ACL",
	} {
		if got := WithArticle(ResourceName(resourceType)); got != want {
			t.Errorf("%s: %q, want %q", resourceType, got, want)
		}
	}
	for noun, want := range map[string]string{"EC2 instance": "an EC2 instance", "user": "a user", "unused value": "an unused value", "": ""} {
		if got := WithArticle(noun); got != want {
			t.Errorf("%q: %q, want %q", noun, got, want)
		}
	}
}
