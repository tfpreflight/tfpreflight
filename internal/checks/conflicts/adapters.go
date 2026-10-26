package conflicts

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
)

// The SDK has typed clients rather than a call-by-name API, so a service without
// a lookup spec contributes a small adapter. An adapter answers only whether AWS
// has an identity.

// SageMakerModelPackageGroups answers whether a model package group exists.
type SageMakerModelPackageGroups struct{ Client *sagemaker.Client }

// Service is the AWS service the adapter answers for.
func (SageMakerModelPackageGroups) Service() string { return "sagemaker" }

// Supports reports whether op is the operation the adapter implements.
func (SageMakerModelPackageGroups) Supports(op string) bool { return op == "DescribeModelPackageGroup" }

// Lookup asks SageMaker whether the model package group exists.
func (a SageMakerModelPackageGroups) Lookup(ctx context.Context, request LookupRequest) (Outcome, error) {
	_, err := a.Client.DescribeModelPackageGroup(ctx, &sagemaker.DescribeModelPackageGroupInput{ModelPackageGroupName: &request.Identity})
	if err == nil {
		return OutcomeExists, nil
	}
	// SageMaker reports a missing group as a ValidationException, not a not-
	// found type, so the message is the signal. Anything else stays unknown.
	if sageMakerAbsent(err) {
		return OutcomeNotFound, nil
	}
	return OutcomeUnknown, err
}

func sageMakerAbsent(err error) bool {
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "does not exist") || strings.Contains(text, "validationexception") && strings.Contains(text, "not found")
}
