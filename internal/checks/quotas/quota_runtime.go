package quotas

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// QuotaInspector supplies the two AWS facts a quota verdict needs, so the
// runtime can be tested without AWS.
type QuotaInspector interface {
	Limit(ctx context.Context, serviceCode, quotaCode string) Measurement
	Usage(ctx context.Context, metric *UsageMetric) Measurement
	Counter(ctx context.Context, counter *UsageCounter, input UsageContext) Measurement
}

// LoadQuotaRules returns the quota knowledge for exactly this provider version.
// There is no fallback to a neighbouring version: a release can change which
// service a resource calls, and so which quota it consumes.
func LoadQuotaRules(version string) (map[string]Rule, bool, error) {
	if version == "" {
		return nil, false, nil
	}
	data, err := packs.ReadFile("aws/generated/quota-aws-" + version + ".json")
	if err != nil {
		return nil, false, nil
	}
	var document struct {
		ProviderVersion string `json:"provider_version"`
		Rules           []Rule `json:"rules"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, false, fmt.Errorf("parse generated AWS quota rules: %w", err)
	}
	if document.ProviderVersion != version {
		return nil, false, nil
	}
	rules := make(map[string]Rule, len(document.Rules))
	for _, rule := range document.Rules {
		rules[rule.Resource] = rule
	}
	if counterData, err := packs.ReadFile("aws/generated/quota-counter-aws-" + version + ".json"); err == nil {
		var counterDocument struct {
			ProviderVersion string `json:"provider_version"`
			Rules           []Rule `json:"rules"`
		}
		if err := json.Unmarshal(counterData, &counterDocument); err != nil {
			return nil, false, fmt.Errorf("parse generated AWS quota counters: %w", err)
		}
		if counterDocument.ProviderVersion != version {
			return nil, false, fmt.Errorf("generated AWS quota counters are for provider %s, not %s", counterDocument.ProviderVersion, version)
		}
		for _, rule := range counterDocument.Rules {
			if _, duplicate := rules[rule.Resource]; duplicate {
				return nil, false, fmt.Errorf("generated AWS quota counter duplicates metric rule for %s", rule.Resource)
			}
			rules[rule.Resource] = rule
		}
	}
	return rules, true, nil
}

// PredictQuotas evaluates the planned changes against the quota knowledge. Each
// resource type is evaluated once, against the combined consumption of its
// changes, because a quota counts the total.
func PredictQuotas(ctx context.Context, changes []model.PlannedChange, rules map[string]Rule, inspector QuotaInspector, vcpu VCPUResolver) []model.Finding {
	if len(rules) == 0 || inspector == nil {
		return nil
	}
	var findings []model.Finding
	for _, resourceType := range plannedResourceTypes(changes) {
		rule, governed := rules[resourceType]
		if !governed {
			continue
		}
		planned := PlannedConsumption(changes, rule, vcpu)
		if planned.Known && planned.Value == 0 {
			// Nothing is added, so this plan cannot cross the quota.
			continue
		}
		decision := Evaluate(
			inspector.Limit(ctx, rule.ServiceCode, rule.QuotaCode),
			currentUsage(ctx, inspector, rule, changes),
			planned,
		)
		if decision.Blocking() && !rule.BlockingSafe() {
			decision.Verdict = VerdictUnknown
			decision.Reason = "the quota limit and usage were measured, but the resource-to-quota/count/scope semantic chain is not independently verified"
		}
		if decision.Verdict == VerdictWithin {
			continue
		}
		findings = append(findings, Finding(rule, firstAddressOf(changes, resourceType), decision))
	}
	return findings
}

func currentUsage(ctx context.Context, inspector QuotaInspector, rule Rule, changes []model.PlannedChange) Measurement {
	if rule.Usage != nil {
		return inspector.Usage(ctx, rule.Usage)
	}
	if rule.Counter != nil {
		return inspector.Counter(ctx, rule.Counter, UsageContext{Resource: rule.Resource, Changes: changes})
	}
	return Unknown("quota knowledge has neither a CloudWatch metric nor a generated usage counter")
}

// plannedResourceTypes lists the AWS resource types a plan touches, in a stable
// order so findings do not reshuffle between runs.
func plannedResourceTypes(changes []model.PlannedChange) []string {
	seen := map[string]bool{}
	var types []string
	for _, change := range changes {
		if model.NormalizeProvider(change.ProviderName) != model.ProviderAWS || seen[change.ResourceType] {
			continue
		}
		seen[change.ResourceType] = true
		types = append(types, change.ResourceType)
	}
	return types
}

func firstAddressOf(changes []model.PlannedChange, resourceType string) string {
	for _, change := range changes {
		if change.ResourceType == resourceType {
			return change.Address
		}
	}
	return resourceType
}

// ApplyQuotaCoverage records, per resource, how completely the quota question
// was answered. A type with no known quota is "no quota rule", not "not
// applicable": the result says tfpreflight knows no quota, not that none
// exists.
func ApplyQuotaCoverage(coverage *model.Coverage, changes []model.PlannedChange, rules map[string]Rule, loaded bool, findings []model.Finding) {
	byAddress := map[string]model.PlannedChange{}
	for _, change := range changes {
		byAddress[change.Address] = change
	}
	// A quota is decided once per resource type and reported on its first
	// resource, so an unverified quota leaves every resource of the type open.
	unverified := map[string]bool{}
	for _, finding := range findings {
		if finding.ID == "aws.quota-unverified" {
			unverified[byAddress[finding.Resource].ResourceType] = true
		}
	}
	for index := range coverage.Resources {
		resource := &coverage.Resources[index]
		change, known := byAddress[resource.Resource]
		if !known {
			continue
		}
		switch {
		case !loaded:
			// No quota knowledge ships for this provider version.
			resource.Quota = model.CheckUnsupported
		case unverified[change.ResourceType]:
			resource.Quota = model.CheckPartialUnresolvedAuthorization
		default:
			if _, governed := rules[change.ResourceType]; governed {
				resource.Quota = model.CheckChecked
				continue
			}
			// No quota is known for this resource type, so there was nothing
			// to check.
			resource.Quota = model.CheckNoQuotaRule
		}
	}
}
