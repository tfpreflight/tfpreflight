package quotas

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

const standardOnDemandVCPUQuotaCode = "L-1216C47A"

// VerifiedQuotaCheck is a built-in quota check proven with controlled AWS
// evidence. Generated quota rules stay inferred until their resource, quota and
// scope are verified independently.
type VerifiedQuotaCheck struct {
	ID        string
	Resource  string
	QuotaCode string
	Trust     string
}

// VerifiedQuotaChecks lists the built-in quota checks backed by verified
// evidence.
func VerifiedQuotaChecks() []VerifiedQuotaCheck {
	return []VerifiedQuotaCheck{{
		ID: "aws.ec2-standard-on-demand-vcpu-quota", Resource: "aws_instance",
		QuotaCode: standardOnDemandVCPUQuotaCode, Trust: "verified",
	}}
}

// EC2InstanceTypeAPI is the EC2 call the vCPU check needs, so tests can
// substitute it.
type EC2InstanceTypeAPI interface {
	DescribeInstanceTypes(context.Context, *ec2.DescribeInstanceTypesInput, ...func(*ec2.Options)) (*ec2.DescribeInstanceTypesOutput, error)
}

type serviceQuotaAPI interface {
	GetServiceQuota(context.Context, *servicequotas.GetServiceQuotaInput, ...func(*servicequotas.Options)) (*servicequotas.GetServiceQuotaOutput, error)
}

// EC2QuotaRequirement is one planned instance launch the vCPU quota applies to.
// internal/aws reads it for coverage.
type EC2QuotaRequirement struct {
	Change       model.PlannedChange
	InstanceType string
	Region       string
}

type quotaResolver func(packs.ResolvedRule) (EC2QuotaRequirement, bool)

var quotaResolvers = map[string]quotaResolver{
	"ec2_standard_vcpu": resolveEC2StandardVCPUQuota,
}

// PredictEC2VCPUQuota checks whether one planned m6i instance alone exceeds the
// account's Standard On-Demand EC2 vCPU quota. It does not add current usage or
// combine planned instances.
func PredictEC2VCPUQuota(ctx context.Context, config awssdk.Config, rules []packs.ResolvedRule) ([]model.Finding, error) {
	requirements := EC2QuotaRequirements(rules)
	if len(requirements) == 0 {
		return nil, nil
	}

	var findings []model.Finding
	for _, requirement := range requirements {
		ec2Client, quotaClient := newEC2QuotaClients(config, requirement.Region)
		findings = append(findings, checkEC2VCPUQuota(ctx, requirement, ec2Client, quotaClient)...)
	}
	return findings, nil
}

func newEC2QuotaClients(config awssdk.Config, region string) (*ec2.Client, *servicequotas.Client) {
	ec2Client := ec2.NewFromConfig(config, func(options *ec2.Options) {
		options.Region = region
	})
	quotaClient := servicequotas.NewFromConfig(config, func(options *servicequotas.Options) {
		options.Region = region
	})
	return ec2Client, quotaClient
}

// EC2QuotaRequirements returns the planned launches the vCPU check applies to:
// those whose instance type and region are known before apply.
func EC2QuotaRequirements(rules []packs.ResolvedRule) []EC2QuotaRequirement {
	var requirements []EC2QuotaRequirement
	for _, rule := range rules {
		if rule.Action.Quota == nil {
			continue
		}
		resolver, found := quotaResolvers[rule.Action.Quota.Type]
		if found {
			if requirement, ok := resolver(rule); ok {
				requirements = append(requirements, requirement)
			}
		}
	}
	return requirements
}

func resolveEC2StandardVCPUQuota(rule packs.ResolvedRule) (EC2QuotaRequirement, bool) {
	instanceType, instanceKnown := packs.ValueForField(rule.Change, rule.Action.Quota.InstanceTypeField)
	region, regionKnown := packs.ValueForField(rule.Change, rule.Action.Quota.RegionField)
	if !instanceKnown || !regionKnown || !hasPrefix(instanceType, rule.Action.Quota.InstanceTypePrefix) {
		return EC2QuotaRequirement{}, false
	}
	return EC2QuotaRequirement{Change: rule.Change, InstanceType: instanceType, Region: region}, true
}

func checkEC2VCPUQuota(ctx context.Context, requirement EC2QuotaRequirement, ec2Client EC2InstanceTypeAPI, quotaClient serviceQuotaAPI) []model.Finding {
	instanceTypes, err := ec2Client.DescribeInstanceTypes(ctx, &ec2.DescribeInstanceTypesInput{
		InstanceTypes: []types.InstanceType{types.InstanceType(requirement.InstanceType)},
	})
	if err != nil || len(instanceTypes.InstanceTypes) == 0 || instanceTypes.InstanceTypes[0].VCpuInfo == nil || instanceTypes.InstanceTypes[0].VCpuInfo.DefaultVCpus == nil {
		// Without a vCPU count from EC2 there is nothing to compare, so no
		// finding.
		return nil
	}
	requiredVCPUs := *instanceTypes.InstanceTypes[0].VCpuInfo.DefaultVCpus

	quota, err := quotaClient.GetServiceQuota(ctx, &servicequotas.GetServiceQuotaInput{
		ServiceCode: awssdk.String("ec2"),
		QuotaCode:   awssdk.String(standardOnDemandVCPUQuotaCode),
	})
	if err != nil || quota.Quota == nil || quota.Quota.Value == nil {
		return []model.Finding{quotaUnavailableFinding(requirement, err)}
	}
	if float64(requiredVCPUs) <= *quota.Quota.Value {
		return nil
	}
	return []model.Finding{quotaExceededFinding(requirement, requiredVCPUs, *quota.Quota.Value)}
}

func quotaExceededFinding(requirement EC2QuotaRequirement, requiredVCPUs int32, quota float64) model.Finding {
	return model.Finding{
		ID:         "aws.ec2-standard-on-demand-vcpu-quota",
		Provider:   "aws",
		Resource:   requirement.Change.Address,
		Category:   "quota",
		Severity:   model.SeverityError,
		Confidence: model.ConfidenceHigh,
		Title:      "Apply will likely fail",
		Operation:  "Launch " + requirement.InstanceType,
		Problem: fmt.Sprintf(
			"This instance requires %d vCPUs, but the AWS account quota allows only %s Standard On-Demand vCPUs.",
			requiredVCPUs, formatQuota(quota),
		),
		Details: []model.Detail{
			{Label: "Required", Value: fmt.Sprintf("%d vCPUs", requiredVCPUs)},
			{Label: "Account quota", Value: fmt.Sprintf("%s vCPUs", formatQuota(quota))},
			{Label: "Quota", Value: "Running On-Demand Standard instances\n" + standardOnDemandVCPUQuotaCode},
		},
		Explanation: "AWS is expected to reject the EC2 launch during terraform apply because the requested capacity exceeds the account quota.",
		Remediation: "Request a quota increase or use a smaller instance type.",
		Brief: fmt.Sprintf("Instance type %s needs %d vCPUs; the account's Standard On-Demand quota allows %s.",
			requirement.InstanceType, requiredVCPUs, formatQuota(quota)),
		Next: "Fix: request a quota increase, or use a smaller instance type.",
	}
}

func quotaUnavailableFinding(requirement EC2QuotaRequirement, err error) model.Finding {
	note := "AWS did not return the Standard On-Demand EC2 vCPU quota."
	if err != nil {
		note = "AWS quota lookup failed: " + err.Error()
	}
	return model.Finding{
		ID:          "aws.ec2-standard-on-demand-vcpu-quota-unavailable",
		Provider:    "aws",
		Resource:    requirement.Change.Address,
		Category:    "quota",
		Severity:    model.SeverityInfo,
		Confidence:  model.ConfidenceLow,
		Title:       "EC2 quota could not be verified",
		Operation:   "Launch " + requirement.InstanceType,
		Explanation: "Could not retrieve the Standard On-Demand EC2 vCPU quota, so tfpreflight cannot predict whether this launch will exceed it.",
		Notes:       []string{note},
		Brief:       "Could not read the Standard On-Demand vCPU quota for instance type " + requirement.InstanceType + ".",
		Next:        "Check: look this quota up in the Service Quotas console.",
	}
}

func formatQuota(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}

// hasPrefix compares case-insensitively: an instance type in mixed case names
// the same family.
func hasPrefix(value, prefix string) bool {
	return strings.HasPrefix(strings.ToLower(value), strings.ToLower(prefix))
}
