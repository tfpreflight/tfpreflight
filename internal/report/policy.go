package report

import (
	"fmt"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

// The values of --fail-on.
const (
	FailOnError   = "error"
	FailOnWarning = "warning"
)

// Policy is when a run exits 1. By default only verified blocking findings do;
// FailOn "warning" adds warnings, and FailOnPartial a check that could not
// complete. Source is where the policy came from.
type Policy struct {
	FailOn        string `json:"fail_on"`
	FailOnPartial bool   `json:"fail_on_partial"`
	Source        string `json:"source"`
}

// DefaultPolicy blocks only on verified findings.
var DefaultPolicy = Policy{FailOn: FailOnError, Source: "default"}

func (p Policy) normal() Policy {
	if p.FailOn == "" {
		p.FailOn = FailOnError
	}
	if p.Source == "" {
		p.Source = "default"
	}
	return p
}

// Line is the policy as the output header states it.
func (p Policy) Line() string {
	p = p.normal()
	line := "Fails on: blocking findings"
	if p.FailOn == FailOnWarning {
		line += ", warnings"
	}
	if p.FailOnPartial {
		line += ", partial checks"
	}
	return fmt.Sprintf("%s (from %s)", line, p.Source)
}

// isWarning reports whether a finding counts as a warning: neither blocking nor
// informational.
func isWarning(finding model.Finding) bool {
	return !isBlocking(finding) && finding.Severity != model.SeverityInfo
}

// Failure says why the report fails under its policy, and the JSON exit
// classification; "" when it passes.
func (r Report) Failure() (reason, classification string) {
	policy := r.Policy.normal()
	switch {
	case r.Summary.Blocking > 0:
		return fmt.Sprintf("%d blocking findings", r.Summary.Blocking), "blocking_findings"
	case policy.FailOn == FailOnWarning && r.Summary.Warnings > 0:
		return fmt.Sprintf("%d warnings (--fail-on warning)", r.Summary.Warnings), "warnings"
	case policy.FailOnPartial && r.Summary.Partial > 0:
		return fmt.Sprintf("%d resources partially checked (--fail-on-partial)", r.Summary.Partial), "partial"
	}
	return "", ""
}
