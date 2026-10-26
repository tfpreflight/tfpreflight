package conflicts

import (
	"context"
	"errors"
	"fmt"

	"github.com/tfpreflight/tfpreflight/internal/packs"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

type s3HeadBucketAPI interface {
	HeadBucket(context.Context, *s3.HeadBucketInput, ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
}

type bucketRequirement struct {
	change model.PlannedChange
	bucket string
	region string
}

type conflictResolver func(packs.ResolvedRule) (bucketRequirement, bool)

var conflictResolvers = map[string]conflictResolver{
	"s3_bucket_exists": resolveS3BucketConflict,
}

// PredictBucketConflicts checks whether a planned S3 bucket with a known name
// already exists, using the inspection credentials, not --principal.
func PredictBucketConflicts(ctx context.Context, config awssdk.Config, rules []packs.ResolvedRule) ([]model.Finding, error) {
	requirements := bucketRequirements(rules)
	if len(requirements) == 0 {
		return nil, nil
	}
	client := newS3Client(config, requirements[0].region)
	return checkBucketConflicts(ctx, requirements, client)
}

func newS3Client(config awssdk.Config, region string) *s3.Client {
	if region == "" {
		return s3.NewFromConfig(config)
	}
	return s3.NewFromConfig(config, func(options *s3.Options) {
		options.Region = region
	})
}

func bucketRequirements(rules []packs.ResolvedRule) []bucketRequirement {
	var requirements []bucketRequirement
	for _, rule := range rules {
		if rule.Action.Conflict == nil {
			continue
		}
		resolver, found := conflictResolvers[rule.Action.Conflict.Type]
		if found {
			if requirement, ok := resolver(rule); ok {
				requirements = append(requirements, requirement)
			}
		}
	}
	return requirements
}

func resolveS3BucketConflict(rule packs.ResolvedRule) (bucketRequirement, bool) {
	bucket, ok := packs.ValueForField(rule.Change, rule.Action.Conflict.IdentityField)
	if !ok {
		return bucketRequirement{}, false
	}
	region, _ := packs.ValueForField(rule.Change, "region")
	return bucketRequirement{change: rule.Change, bucket: bucket, region: region}, true
}

func checkBucketConflicts(ctx context.Context, requirements []bucketRequirement, client s3HeadBucketAPI) ([]model.Finding, error) {
	var findings []model.Finding
	for _, requirement := range requirements {
		_, err := client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &requirement.bucket})
		if err == nil || statusCode(err) == 301 {
			findings = append(findings, bucketConflictFinding(requirement))
			continue
		}
		// 404 means the name is free. Anything else, 403 included, may be
		// our own permissions, so it is reported as unverified, not a conflict.
		if statusCode(err) != 404 {
			findings = append(findings, bucketVerificationUnavailableFinding(requirement, err))
		}
	}
	return findings, nil
}

type httpStatusError interface {
	HTTPStatusCode() int
}

func statusCode(err error) int {
	var responseError httpStatusError
	if errors.As(err, &responseError) {
		return responseError.HTTPStatusCode()
	}
	return 0
}

func bucketConflictFinding(requirement bucketRequirement) model.Finding {
	return model.Finding{
		ID:          "aws.s3-bucket-conflict",
		Provider:    "aws",
		Resource:    requirement.change.Address,
		Category:    "resource-conflict",
		Severity:    model.SeverityError,
		Confidence:  model.ConfidenceHigh,
		Title:       "Apply will likely fail",
		Operation:   "Create S3 bucket\n" + requirement.bucket,
		Problem:     "An S3 bucket with this name already exists.",
		Explanation: "Terraform plans to create this bucket, but AWS already has a bucket using this globally unique name.",
		Remediation: "Use a different bucket name or import the existing bucket into Terraform if Terraform should manage it.",
		Brief:       fmt.Sprintf("Bucket name %q is already taken.", requirement.bucket),
		Next:        "Fix: use a different name, or import the existing bucket.",
	}
}

func bucketVerificationUnavailableFinding(requirement bucketRequirement, err error) model.Finding {
	return model.Finding{
		ID:          "aws.s3-bucket-verification-unavailable",
		Provider:    "aws",
		Resource:    requirement.change.Address,
		Category:    "resource-conflict",
		Severity:    model.SeverityInfo,
		Confidence:  model.ConfidenceLow,
		Title:       "S3 bucket availability could not be verified",
		Operation:   "Create S3 bucket\n" + requirement.bucket,
		Explanation: "Could not verify whether the S3 bucket already exists because the current AWS identity cannot inspect it.",
		Notes:       []string{verificationErrorNote(err)},
		AWSError:    verificationErrorNote(err),
		Brief:       fmt.Sprintf("Could not check whether bucket name %q is taken.", requirement.bucket),
		Next:        "Check: " + verificationErrorNote(err),
	}
}

func verificationErrorNote(err error) string {
	if status := statusCode(err); status != 0 {
		return fmt.Sprintf("AWS returned HTTP %d while checking the bucket.", status)
	}
	return "AWS returned an unexpected response while checking the bucket."
}
