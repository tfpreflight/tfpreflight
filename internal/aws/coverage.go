package aws

import (
	"github.com/tfpreflight/tfpreflight/internal/checks/conflicts"
	"github.com/tfpreflight/tfpreflight/internal/checks/permissions"
	"github.com/tfpreflight/tfpreflight/internal/checks/quotas"
	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

func buildCoverage(changes []model.PlannedChange, rules []packs.ResolvedRule, context model.AWSContext, findings []model.Finding, generatedLoaded bool) model.Coverage {
	coverage := model.Coverage{ProviderKnowledge: model.CheckChecked}
	if !generatedLoaded {
		coverage.ProviderKnowledge = model.CheckUnsupported
	}
	quotaRequirements := quotas.EC2QuotaRequirements(rules)
	for _, change := range changes {
		if model.NormalizeProvider(change.ProviderName) != model.ProviderAWS {
			continue
		}
		resource := model.ResourceCoverage{Resource: change.Address, Permissions: model.CheckNotApplicable, Conflicts: model.CheckNotApplicable, Quota: model.CheckNotApplicable}
		resource.Trust = ruleTrust(change, rules)
		if hasPermissionRequirement(change, rules) {
			applyPermissionCoverage(&resource, change, rules, context.ApplyIdentityKnown)
		}
		if hasResolvableConflict(change, rules) {
			resource.Conflicts = statusForFinding(change.Address, "resource-conflict", findings)
		}
		if hasQuotaRequirement(change, quotaRequirements) {
			resource.Quota = statusForFinding(change.Address, "quota", findings)
		}
		if resource.Permissions == model.CheckNotApplicable && resource.Conflicts == model.CheckNotApplicable && resource.Quota == model.CheckNotApplicable {
			resource.Permissions = model.CheckUnsupported
		}
		coverage.Resources = append(coverage.Resources, resource)
	}
	return coverage
}

// applyPermissionCoverage sets a resource's permission status: checked when the
// apply identity is known, skipped otherwise. An operation with no IAM action,
// and one whose code path the plan cannot decide, both make the result partial;
// "checked" would present either as a whole answer.
func applyPermissionCoverage(resource *model.ResourceCoverage, change model.PlannedChange, rules []packs.ResolvedRule, applyIdentityKnown bool) {
	unresolved, unevaluable := permissions.Gaps(change, rules)
	resource.UnresolvedAuthorizationOperations = unresolved
	resource.UnevaluableConditionOperations = unevaluable
	switch {
	case !applyIdentityKnown:
		resource.Permissions = model.CheckSkipped
	case len(unresolved) > 0:
		resource.Permissions = model.CheckPartialUnresolvedAuthorization
	case len(unevaluable) > 0:
		resource.Permissions = model.CheckPartialUnevaluableCondition
	default:
		resource.Permissions = model.CheckChecked
	}
}

// applyResolverCoverage sets the conflict status of every type the generated
// resolver checks. A type has one conflict source, so a type the resolver has no
// rule for keeps the status it had.
func applyResolverCoverage(coverage *model.Coverage, entries []conflicts.Coverage) {
	byAddress := map[string]conflicts.Status{}
	for _, entry := range entries {
		if entry.Status != conflicts.StatusNoRule {
			byAddress[entry.Resource] = entry.Status
		}
	}
	for index := range coverage.Resources {
		resource := &coverage.Resources[index]
		status, checked := byAddress[resource.Resource]
		if !checked {
			continue
		}
		resource.Conflicts = status.CheckStatus()
	}
}

// applyUncheckedPermissions makes permissions partial, with the reason, for
// every resource IAM could not simulate.
func applyUncheckedPermissions(coverage *model.Coverage, unchecked permissions.Unchecked) {
	for index := range coverage.Resources {
		resource := &coverage.Resources[index]
		if reason, found := unchecked[resource.Resource]; found {
			resource.Permissions = model.CheckPartialSimulationUnavailable
			resource.PermissionsUnavailable = reason
		}
	}
}

func ruleTrust(change model.PlannedChange, rules []packs.ResolvedRule) string {
	for _, rule := range rules {
		if rule.Change.Address != change.Address {
			continue
		}
		for _, operation := range rule.Action.Operations {
			if operation.Trust == "generated" {
				return "generated"
			}
		}
		return "verified"
	}
	return "unsupported"
}

func hasPermissionRequirement(change model.PlannedChange, rules []packs.ResolvedRule) bool {
	for _, rule := range rules {
		if rule.Change.Address == change.Address && len(rule.Action.Operations) > 0 {
			return true
		}
	}
	return false
}

func hasResolvableConflict(change model.PlannedChange, rules []packs.ResolvedRule) bool {
	for _, rule := range rules {
		if rule.Change.Address != change.Address || rule.Action.Conflict == nil {
			continue
		}
		switch rule.Action.Conflict.Type {
		case "s3_bucket_exists", "iam_name_exists":
			if _, ok := packs.ValueForField(rule.Change, rule.Action.Conflict.IdentityField); ok {
				return true
			}
		}
	}
	return false
}

func hasQuotaRequirement(change model.PlannedChange, requirements []quotas.EC2QuotaRequirement) bool {
	for _, requirement := range requirements {
		if requirement.Change.Address == change.Address {
			return true
		}
	}
	return false
}

func statusForFinding(resource, category string, findings []model.Finding) model.CheckStatus {
	for _, finding := range findings {
		if finding.Resource == resource && finding.Category == category && finding.Severity != model.SeverityError {
			return model.CheckUnverifiable
		}
	}
	return model.CheckChecked
}

// unsupportedProviderFinding reports that no knowledge ships for the provider
// version Terraform selected. It is a warning: nothing is known to be wrong, but
// nothing was checked. A neighbouring version's pack would be worse than
// nothing, since a release can change which API a resource calls.
func unsupportedProviderFinding(version string) model.Finding {
	described := version
	if described == "" {
		described = "an undetermined version"
	} else {
		described = "version " + described
	}
	return model.Finding{
		ID:          "aws.provider-version-unsupported",
		Provider:    "aws",
		Category:    "coverage",
		Severity:    model.SeverityWarning,
		Confidence:  model.ConfidenceHigh,
		Title:       "AWS provider version is not supported",
		Operation:   "Load the AWS rules for " + described,
		Problem:     "tfpreflight has no rules for AWS provider " + described + ", so no AWS checks ran for this plan.",
		Explanation: "Rules are tied to an exact provider version because a release can change which AWS API a resource calls. tfpreflight will not answer from another version's rules, so it reports nothing rather than something that may no longer be true.",
		Remediation: "Use a provider version tfpreflight has rules for (see tfpreflight version), or run tfpreflight update.",
		Brief:       "There are no rules for AWS provider " + described + ", so no AWS checks ran.",
		Next:        "Fix: run tfpreflight update, or use a version tfpreflight version lists.",
	}
}
