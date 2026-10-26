package quotas

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cloudwatchtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
	servicequotastypes "github.com/aws/aws-sdk-go-v2/service/servicequotas/types"
)

// QuotaLimitAPI reads one quota's applied value.
type QuotaLimitAPI interface {
	GetServiceQuota(context.Context, *servicequotas.GetServiceQuotaInput, ...func(*servicequotas.Options)) (*servicequotas.GetServiceQuotaOutput, error)
	GetAWSDefaultServiceQuota(context.Context, *servicequotas.GetAWSDefaultServiceQuotaInput, ...func(*servicequotas.Options)) (*servicequotas.GetAWSDefaultServiceQuotaOutput, error)
}

// ResolveLimit reads the quota value that applies to this account, since a
// raised quota is why an account differs from the default. Every failure, such
// as AccessDenied, throttling or an unpublished quota code, gives an unknown
// limit with the reason, never a default number.
func ResolveLimit(ctx context.Context, api QuotaLimitAPI, serviceCode, quotaCode string) Measurement {
	if serviceCode == "" || quotaCode == "" {
		return Unknown("no quota code is known for this resource")
	}
	applied, err := api.GetServiceQuota(ctx, &servicequotas.GetServiceQuotaInput{
		ServiceCode: aws.String(serviceCode), QuotaCode: aws.String(quotaCode),
	})
	if err == nil && applied.Quota != nil && applied.Quota.Value != nil {
		return Known(*applied.Quota.Value)
	}
	// A quota never adjusted is absent from the applied list, so AWS's default
	// is the value in force.
	var notFound *servicequotastypes.NoSuchResourceException
	if err == nil || errors.As(err, &notFound) {
		fallback, defaultErr := api.GetAWSDefaultServiceQuota(ctx, &servicequotas.GetAWSDefaultServiceQuotaInput{
			ServiceCode: aws.String(serviceCode), QuotaCode: aws.String(quotaCode),
		})
		if defaultErr != nil {
			return Unknown("AWS did not return a default for " + quotaCode + ": " + defaultErr.Error())
		}
		if fallback.Quota == nil || fallback.Quota.Value == nil {
			return Unknown("AWS published no value for quota " + quotaCode)
		}
		return Known(*fallback.Quota.Value)
	}
	return Unknown("Service Quotas could not be read for " + quotaCode + ": " + err.Error())
}

// MetricAPI reads CloudWatch metric statistics.
type MetricAPI interface {
	GetMetricStatistics(context.Context, *cloudwatch.GetMetricStatisticsInput, ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricStatisticsOutput, error)
}

// ResolveUsage reads current usage from the CloudWatch metric AWS attaches to
// the quota, the same way for every quota. A quota that publishes none gives
// unknown usage, not an assumption that nothing is in use.
func ResolveUsage(ctx context.Context, api MetricAPI, metric *UsageMetric, window time.Duration, now time.Time) Measurement {
	if metric == nil || metric.MetricName == "" {
		return Unknown("AWS publishes no usage metric for this quota, so current usage cannot be measured")
	}
	dimensions := make([]cloudwatchtypes.Dimension, 0, len(metric.Dimensions))
	for name, value := range metric.Dimensions {
		dimensions = append(dimensions, cloudwatchtypes.Dimension{Name: aws.String(name), Value: aws.String(value)})
	}
	statistic := cloudwatchtypes.StatisticMaximum
	if metric.Statistic == "Average" {
		statistic = cloudwatchtypes.StatisticAverage
	}
	output, err := api.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String(metric.Namespace),
		MetricName: aws.String(metric.MetricName),
		Dimensions: dimensions,
		StartTime:  aws.Time(now.Add(-window)),
		EndTime:    aws.Time(now),
		Period:     aws.Int32(int32(window.Seconds())),
		Statistics: []cloudwatchtypes.Statistic{statistic},
	})
	if err != nil {
		return Unknown("CloudWatch usage could not be read: " + err.Error())
	}
	if len(output.Datapoints) == 0 {
		// No datapoint can mean zero usage or a metric that is not published.
		// Reading it as zero would invent headroom.
		return Unknown("CloudWatch returned no usage datapoints for " + metric.MetricName)
	}
	latest := output.Datapoints[0]
	for _, point := range output.Datapoints {
		if point.Timestamp != nil && latest.Timestamp != nil && point.Timestamp.After(*latest.Timestamp) {
			latest = point
		}
	}
	value := latest.Maximum
	if statistic == cloudwatchtypes.StatisticAverage {
		value = latest.Average
	}
	if value == nil {
		return Unknown("CloudWatch returned a datapoint with no value for " + metric.MetricName)
	}
	return Known(*value)
}
