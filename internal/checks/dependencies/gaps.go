package dependencies

import (
	"strings"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

// Why each kind of dependency gap happens, as the text output states it once.
const (
	noLookupWhy  = "This tfpreflight cannot run the lookup for this rule, so it was not checked. Install the newest tfpreflight release; if you already run it, the lookup is not built yet."
	noAnswerWhy  = "The lookup got no usable answer, such as access denied, a timeout or an unreachable AWS endpoint, so the referenced resource was neither confirmed nor ruled out."
	undecidedWhy = "The plan does not hold enough to decide this check, so it was not run."
)

// CoverageGaps turns every partial result into a coverage note, one finding
// per resource, so the report's Not checked list names it and says why. A note
// is information only: not knowing is never a failure.
func CoverageGaps(results []Result) []model.Finding {
	var order []string
	gaps := map[string][]model.Gap{}
	for _, result := range results {
		if result.Verdict != VerdictPartial {
			continue
		}
		if _, listed := gaps[result.Address]; !listed {
			order = append(order, result.Address)
		}
		gaps[result.Address] = append(gaps[result.Address], gapOf(result))
	}
	findings := make([]model.Finding, 0, len(order))
	for _, address := range order {
		findings = append(findings, gapFinding(address, gaps[address]))
	}
	return findings
}

// UnreadGap is the coverage note for a resource whose dependencies could not be
// checked at all because the plan's configuration could not be read.
func UnreadGap(address string) model.Finding {
	return gapFinding(address, []model.Gap{{Summary: "the plan's configuration could not be read", Why: undecidedWhy}})
}

func gapOf(result Result) model.Gap {
	summary := result.Reason
	if result.Attribute != "" {
		summary = result.Attribute + ": " + summary
	}
	why := undecidedWhy
	switch result.Cause {
	case CauseNoLookup:
		why = noLookupWhy
	case CauseNoAnswer:
		why = noAnswerWhy
	}
	return model.Gap{Summary: summary, Why: why}
}

func gapFinding(address string, gaps []model.Gap) model.Finding {
	summaries := make([]string, len(gaps))
	for i, gap := range gaps {
		summaries[i] = gap.Summary
	}
	return model.Finding{
		ID:          "aws.dependency-coverage-incomplete",
		Provider:    "aws",
		Resource:    address,
		Category:    "dependency",
		Severity:    model.SeverityInfo,
		Confidence:  model.ConfidenceLow,
		Title:       "Dependency check is incomplete",
		Operation:   "Check what this resource refers to",
		Problem:     "tfpreflight could not finish checking what this resource refers to: " + strings.Join(summaries, "; ") + ".",
		Explanation: "A reference was not confirmed or ruled out. This is a gap in coverage, not a predicted apply failure.",
		Remediation: "Treat this resource's dependency result as partial and confirm the references another way, such as a dry run in a non-production account.",
		Gaps:        gaps,
		Brief:       "Some references were not checked: " + strings.Join(summaries, "; ") + ".",
		Next:        "Check: confirm them another way, such as a dry run in a test account.",
	}
}
