package model

import "strings"

// nameWords are the words of Terraform AWS type names that are written
// differently in prose, mostly initialisms.
var nameWords = map[string]string{
	"acl": "ACL", "acm": "ACM", "alb": "ALB", "ami": "AMI", "api": "API", "apigatewayv2": "API Gateway v2",
	"arn": "ARN", "cloudformation": "CloudFormation", "cloudfront": "CloudFront", "cloudtrail": "CloudTrail",
	"cloudwatch": "CloudWatch", "cors": "CORS", "db": "DB", "dns": "DNS", "dynamodb": "DynamoDB", "ebs": "EBS",
	"ec2": "EC2", "ecr": "ECR", "ecs": "ECS", "efs": "EFS", "eip": "Elastic IP", "eks": "EKS", "elasticache": "ElastiCache",
	"elb": "ELB", "emr": "EMR", "http": "HTTP", "iam": "IAM", "id": "ID", "ip": "IP", "ipv4": "IPv4", "ipv6": "IPv6",
	"kms": "KMS", "lambda": "Lambda", "lb": "load balancer", "msk": "MSK", "nat": "NAT", "nlb": "NLB", "oidc": "OIDC",
	"opensearch": "OpenSearch", "rds": "RDS", "rest": "REST", "route53": "Route 53", "s3": "S3", "saml": "SAML",
	"ses": "SES", "sfn": "Step Functions", "sns": "SNS", "sqs": "SQS", "ssm": "SSM", "sso": "SSO", "sts": "STS",
	"tls": "TLS", "vpc": "VPC", "vpn": "VPN", "waf": "WAF", "wafv2": "WAFv2",
}

// ResourceName is how a Terraform resource type reads in a sentence:
// aws_iam_role is "IAM role", aws_s3_bucket_cors_configuration "S3 bucket CORS
// configuration".
func ResourceName(resourceType string) string {
	words := strings.Split(strings.TrimPrefix(resourceType, "aws_"), "_")
	for i, word := range words {
		if prose, ok := nameWords[word]; ok {
			words[i] = prose
		}
	}
	return strings.Join(words, " ")
}

// Sentence is ResourceName starting a sentence: "IAM role", "Instance".
func Sentence(resourceType string) string {
	name := ResourceName(resourceType)
	if name == "" {
		return name
	}
	return strings.ToUpper(name[:1]) + name[1:]
}

// WithArticle puts "a" or "an" before a noun phrase, by how its first word is
// said: "an S3 bucket", "an IAM role", "a VPC", "an Elastic IP", "a user".
func WithArticle(noun string) string {
	if noun == "" {
		return noun
	}
	first, _, _ := strings.Cut(noun, " ")
	if spelledOut(first) {
		// An initialism is read letter by letter: "an S3", "a VPC".
		if strings.ContainsRune("AEFHILMNORSX", rune(first[0])) {
			return "an " + noun
		}
		return "a " + noun
	}
	lower := strings.ToLower(first)
	if strings.ContainsRune("aeio", rune(lower[0])) || strings.HasPrefix(lower, "un") {
		return "an " + noun
	}
	return "a " + noun
}

// saidAsWords are the capitalized names read as one word, not letter by letter.
var saidAsWords = map[string]bool{"NAT": true, "REST": true, "SAML": true, "WAF": true, "WAFv2": true}

// spelledOut reports whether a word is an initialism: its first two letters
// are capitals, or a capital and a digit, as in IAM, S3 or IPv6.
func spelledOut(word string) bool {
	if saidAsWords[word] || len(word) < 2 || word[0] < 'A' || word[0] > 'Z' {
		return false
	}
	return word[1] >= 'A' && word[1] <= 'Z' || word[1] >= '0' && word[1] <= '9'
}
