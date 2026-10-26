package permissions

import (
	"fmt"
	"sort"
	"strings"

	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// PredictUnresolvedAuthorization reports resources whose permission check cannot
// be complete: part of what the apply does was never checked, and silence would
// let the resource pass. It is a coverage note, not a warning: a denial is not
// known, only not ruled out, so it never fails a run that fails on warnings.
func PredictUnresolvedAuthorization(changes []model.PlannedChange, rules []packs.ResolvedRule) []model.Finding {
	var findings []model.Finding
	for _, change := range changes {
		if model.NormalizeProvider(change.ProviderName) != model.ProviderAWS {
			continue
		}
		unresolved, unevaluable := Gaps(change, rules)
		if len(unresolved)+len(unevaluable) == 0 {
			continue
		}
		findings = append(findings, model.Finding{
			ID:          "aws.permission-coverage-incomplete",
			Provider:    "aws",
			Resource:    change.Address,
			Category:    "permission",
			Severity:    model.SeverityInfo,
			Confidence:  model.ConfidenceLow,
			Title:       "Permission check is incomplete",
			Operation:   operationSummary(append(append([]string(nil), unresolved...), unevaluable...)),
			Problem:     gapProblem(unresolved, unevaluable),
			Explanation: gapExplanation(unresolved, unevaluable),
			Remediation: "Treat this resource's permission result as partial and confirm access to these operations another way, such as a dry run in a non-production account.",
			Gaps:        permissionGaps(unresolved, unevaluable),
			Brief:       "The permissions for these calls were not checked: " + strings.Join(append(append([]string(nil), unresolved...), unevaluable...), ", ") + ".",
			Next:        "Check: confirm access to them another way, such as a dry run in a test account.",
		})
	}
	return findings
}

func gapProblem(unresolved, unevaluable []string) string {
	var parts []string
	if len(unresolved) > 0 {
		parts = append(parts, fmt.Sprintf("tfpreflight could not determine which IAM action authorizes %s.", strings.Join(unresolved, ", ")))
	}
	if len(unevaluable) > 0 {
		parts = append(parts, fmt.Sprintf("tfpreflight found %s that may execute during apply, but cannot yet tell from the plan whether that code path runs: %s.",
			countedOperations(len(unevaluable)), strings.Join(unevaluable, ", ")))
	}
	return strings.Join(parts, " ")
}

func gapExplanation(unresolved, unevaluable []string) string {
	var parts []string
	if len(unresolved) > 0 {
		parts = append(parts, "tfpreflight does not know which IAM action authorizes those operations, and does not guess one from an operation's name.")
	}
	if len(unevaluable) > 0 {
		parts = append(parts, "The provider reaches those operations through a code path the plan does not describe. tfpreflight will not guess whether the path runs, because assuming it does would demand permissions that may never be used, and assuming it does not would hide a real gap.")
	}
	return strings.Join(parts, " ") + " This is a gap in coverage, not a predicted apply failure."
}

// Why each kind of permission gap happens, as the text output states it once.
const (
	unresolvedWhy  = "IAM action unknown: tfpreflight does not know which IAM action AWS checks for the call, so it could not simulate it."
	unevaluableWhy = "May call: the provider makes the call only in some cases, and the plan does not show whether this apply will, so it was not simulated."
)

func permissionGaps(unresolved, unevaluable []string) []model.Gap {
	var gaps []model.Gap
	if len(unresolved) > 0 {
		gaps = append(gaps, model.Gap{Summary: "IAM action unknown for " + strings.Join(unresolved, ", "), Why: unresolvedWhy})
	}
	if len(unevaluable) > 0 {
		gaps = append(gaps, model.Gap{Summary: "may call " + strings.Join(unevaluable, ", "), Why: unevaluableWhy})
	}
	return gaps
}

func countedOperations(count int) string {
	if count == 1 {
		return "1 AWS operation"
	}
	return fmt.Sprintf("%d AWS operations", count)
}

func operationSummary(operations []string) string {
	if len(operations) == 1 {
		return "Call " + operations[0]
	}
	return fmt.Sprintf("Call %d API operations", len(operations))
}

// Gaps sorts a change's operations into the two ways a permission result can be
// incomplete. Every operation is checked, skipped because the plan says its
// condition does not hold, or one of these gaps; none is simply forgotten.
// internal/aws uses the same accounting for coverage.
func Gaps(change model.PlannedChange, rules []packs.ResolvedRule) (unresolved, unevaluable []string) {
	seen := map[string]bool{}
	for _, rule := range rules {
		if rule.Change.Address != change.Address {
			continue
		}
		for _, operation := range rule.Action.Operations {
			name := operation.Service + ":" + operation.Name
			if seen[name] {
				continue
			}
			switch {
			case !operation.ConditionEvaluable():
				// May run during apply; the plan cannot say whether it will.
				seen[name] = true
				unevaluable = append(unevaluable, name)
			case operation.WillRun(change) && operation.Permission == "":
				// Will run, but nothing says which IAM action authorizes it.
				seen[name] = true
				unresolved = append(unresolved, name)
			}
		}
	}
	sort.Strings(unresolved)
	sort.Strings(unevaluable)
	return unresolved, unevaluable
}
