package quotas

import (
	"fmt"
	"strings"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

// Finding reports a quota decision for one resource type. Only a fully
// determined comparison blocks. An unknown verdict is a coverage note naming
// the missing part: a quota check that reports nothing looks the same as one
// that found headroom.
func Finding(rule Rule, address string, decision Decision) model.Finding {
	base := model.Finding{
		Provider:  "aws",
		Resource:  address,
		Category:  "quota",
		Operation: "Consume " + describeQuota(rule),
	}
	if decision.Blocking() {
		base.ID = "aws.quota-exceeded"
		base.Severity, base.Confidence = model.SeverityError, model.ConfidenceHigh
		base.Title = "Apply will likely exceed an AWS quota"
		base.Problem = fmt.Sprintf("%s is limited to %g. The account already uses %g and this plan adds %g, for %g during apply.",
			describeQuota(rule), decision.Limit.Value, decision.Usage.Value, decision.Planned.Value, decision.Expected)
		base.Explanation = "AWS rejects the request that crosses the quota, so terraform apply fails partway through rather than at plan time."
		base.Remediation = remediation(rule)
		base.Brief = fmt.Sprintf("%s allows %g; the account uses %g and this plan adds %g.", upperFirst(describeQuota(rule)), decision.Limit.Value, decision.Usage.Value, decision.Planned.Value)
		base.Next = "Fix: create less, or use another region or account; this quota cannot be raised."
		if rule.Adjustable {
			base.Next = "Fix: request an increase in Service Quotas, or create less."
		}
		return base
	}
	base.ID = "aws.quota-unverified"
	// A partial result is a coverage gap, not a predicted rejection, so it is
	// informational and never fails a run that fails on warnings.
	base.Severity, base.Confidence = model.SeverityInfo, model.ConfidenceLow
	base.Title = "Quota could not be checked"
	base.Problem = fmt.Sprintf("tfpreflight could not determine whether this plan fits within %s: %s.", describeQuota(rule), decision.Reason)
	base.Explanation = "A quota verdict needs the limit, the usage already in the account and the usage the plan adds. One of them was unavailable, so no claim is made either way."
	base.Remediation = "Check this quota manually in the Service Quotas console before applying."
	base.Brief = fmt.Sprintf("Could not check %s: %s.", describeQuota(rule), decision.Reason)
	base.Next = "Check: look this quota up in the Service Quotas console."
	base.Gaps = []model.Gap{{
		Summary: describeQuota(rule) + " not checked: " + decision.Reason,
		Why:     "Quota: a quota check needs the limit, the usage already in the account and what the plan adds; one of them was unavailable.",
	}}
	return base
}

func upperFirst(text string) string {
	if text == "" {
		return text
	}
	return strings.ToUpper(text[:1]) + text[1:]
}

func describeQuota(rule Rule) string {
	if rule.QuotaName != "" {
		return fmt.Sprintf("the %s quota (%s)", rule.QuotaName, rule.QuotaCode)
	}
	return "quota " + rule.QuotaCode
}

func remediation(rule Rule) string {
	if rule.Adjustable {
		return fmt.Sprintf("Request an increase for %s in Service Quotas, or reduce what the plan creates.", describeQuota(rule))
	}
	return fmt.Sprintf("%s cannot be raised, so reduce what the plan creates or spread it across regions or accounts.", describeQuota(rule))
}
