// Package quotas predicts whether a plan would push an AWS account past a
// service quota during apply.
//
// A quota answer has three parts: the limit, the usage already in the account,
// and the usage the plan adds. A prediction needs all three, so the package
// makes an unknown part impossible to ignore rather than easy to default away.
package quotas

import "github.com/tfpreflight/tfpreflight/rules"

// The rule schema is defined in the rules package. These names are the ones
// other packages use with this one.
type (
	// Rule is one quota rule; see [rules.Rule].
	Rule = rules.Rule
	// UsageMetric is the CloudWatch metric current usage is read from; see
	// [rules.UsageMetric].
	UsageMetric = rules.UsageMetric
	// UsageCounter counts current usage through an AWS API; see
	// [rules.UsageCounter].
	UsageCounter = rules.UsageCounter
)
