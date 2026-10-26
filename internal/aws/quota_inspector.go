package aws

import (
	"context"
	"time"

	"github.com/tfpreflight/tfpreflight/internal/checks/quotas"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
	"github.com/tfpreflight/tfpreflight/internal/checks/quotas/counters"
)

// awsQuotaInspector reads limits and usage with the inspection credentials, not
// the apply identity: what the account holds is a fact about the account, not
// about who applies. Every failure is an unknown measurement with its cause, so
// a missing answer is never taken for spare capacity.
type awsQuotaInspector struct {
	quotas   quotas.QuotaLimitAPI
	metrics  quotas.MetricAPI
	counters *counters.Registry
	now      func() time.Time
}

// NewAWSQuotaInspector builds an inspector from the AWS configuration.
func NewAWSQuotaInspector(config awssdk.Config) quotas.QuotaInspector {
	registry := counters.NewRegistry()
	counters.RegisterGenerated(registry, config)
	return &awsQuotaInspector{
		quotas:   servicequotas.NewFromConfig(config),
		metrics:  cloudwatch.NewFromConfig(config),
		counters: registry,
		now:      time.Now,
	}
}

// Limit reads one Service Quotas limit.
func (a *awsQuotaInspector) Limit(ctx context.Context, serviceCode, quotaCode string) quotas.Measurement {
	return quotas.ResolveLimit(ctx, a.quotas, serviceCode, quotaCode)
}

// Usage reads one CloudWatch usage metric.
func (a *awsQuotaInspector) Usage(ctx context.Context, metric *quotas.UsageMetric) quotas.Measurement {
	return quotas.ResolveUsage(ctx, a.metrics, metric, usageWindow, a.now())
}

// Counter runs one generated AWS usage counter.
func (a *awsQuotaInspector) Counter(ctx context.Context, counter *quotas.UsageCounter, input quotas.UsageContext) quotas.Measurement {
	return a.counters.Count(ctx, counter, input)
}

// ec2VCPUResolver gets an instance type's vCPU count from AWS, not from the
// type's name.
type ec2VCPUResolver struct {
	client quotas.EC2InstanceTypeAPI
	ctx    context.Context
}

// VCPUCount returns the EC2 vCPU count for an instance type.
func (e ec2VCPUResolver) VCPUCount(instanceType string) (int32, bool, error) {
	output, err := e.client.DescribeInstanceTypes(e.ctx, &ec2.DescribeInstanceTypesInput{
		InstanceTypes: []ec2types.InstanceType{ec2types.InstanceType(instanceType)},
	})
	if err != nil {
		return 0, false, err
	}
	for _, described := range output.InstanceTypes {
		if described.VCpuInfo != nil && described.VCpuInfo.DefaultVCpus != nil {
			return *described.VCpuInfo.DefaultVCpus, true, nil
		}
	}
	return 0, false, nil
}

// usageWindow is how far back CloudWatch is asked for usage. AWS/Usage metrics
// publish every few minutes, so a short window often returns nothing, which
// reads as unknown.
const usageWindow = 6 * time.Hour
