// Package universal runs provider-independent checks against Terraform changes.
package universal

import "github.com/tfpreflight/tfpreflight/rules/model"

// Run returns the findings of every provider-independent check: destroyed and
// replaced resources, and values unknown until apply.
func Run(changes []model.PlannedChange) []model.Finding {
	findings := destructions(changes)
	findings = append(findings, replacements(changes)...)
	return append(findings, unknownValues(changes)...)
}

func destructions(changes []model.PlannedChange) []model.Finding {
	return findingsForAction(changes, model.ActionDelete, model.Finding{
		ID:         "universal.resource-destruction",
		Category:   "destruction",
		Severity:   model.SeverityWarning,
		Confidence: model.ConfidenceHigh,
		Title:      "Resource will be destroyed.",
		Reason:     "Terraform plans to permanently delete this resource.",
		Brief:      "Terraform will permanently delete this resource.",
		Next:       "Check: nothing still needs it, and its data is backed up.",
	})
}

func replacements(changes []model.PlannedChange) []model.Finding {
	return findingsForAction(changes, model.ActionReplace, model.Finding{
		ID:         "universal.resource-replacement",
		Category:   "replacement",
		Severity:   model.SeverityWarning,
		Confidence: model.ConfidenceHigh,
		Title:      "Resource will be replaced.",
		Reason:     "Terraform plans to destroy and recreate this resource. This may cause downtime or data loss.",
		Brief:      "Terraform will destroy and recreate this resource.",
		Next:       "Check: this can cause downtime or data loss.",
	})
}

func findingsForAction(changes []model.PlannedChange, action model.Action, template model.Finding) []model.Finding {
	var findings []model.Finding
	for _, change := range changes {
		if change.Action != action {
			continue
		}
		finding := template
		finding.Resource = change.Address
		finding.Provider = string(model.NormalizeProvider(change.ProviderName))
		findings = append(findings, finding)
	}
	return findings
}

func unknownValues(changes []model.PlannedChange) []model.Finding {
	var findings []model.Finding
	for _, change := range changes {
		if change.Action != model.ActionCreate && change.Action != model.ActionUpdate && change.Action != model.ActionReplace {
			continue
		}
		if !containsUnknown(change.AfterUnknown) {
			continue
		}
		findings = append(findings, model.Finding{
			ID:         "universal.unknown-values",
			Provider:   string(model.NormalizeProvider(change.ProviderName)),
			Resource:   change.Address,
			Category:   "unknown-values",
			Severity:   model.SeverityInfo,
			Confidence: model.ConfidenceMedium,
			Title:      "Some values are unknown until apply.",
			Reason:     "Certain apply-time checks may not be possible for this resource.",
			Brief:      "Some of this resource's values are not known until apply.",
			Next:       "Check: checks that need those values could not run.",
		})
	}
	return findings
}

func containsUnknown(value any) bool {
	switch current := value.(type) {
	case bool:
		return current
	case map[string]any:
		for _, child := range current {
			if containsUnknown(child) {
				return true
			}
		}
	case []any:
		for _, child := range current {
			if containsUnknown(child) {
				return true
			}
		}
	}
	return false
}
