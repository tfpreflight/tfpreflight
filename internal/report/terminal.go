// Package report turns check results into one ordered report and renders it as
// text, as JSON, and as a redacted support bundle.
package report

import (
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

// Options controls the text output. Details asks for the full output; All
// adds informational findings to it, so it implies Details.
type Options struct {
	All     bool
	Details bool
}

// Render writes the text report: the short summary, or with Details or All the
// full output.
func Render(out io.Writer, report Report, options Options) {
	if !options.Details && !options.All {
		renderSummary(out, report)
		return
	}
	renderDetails(out, report, options)
}

// renderDetails writes the full text report.
func renderDetails(out io.Writer, report Report, options Options) {
	fmt.Fprintln(out, "tfpreflight")
	if report.Selection.Summary != "" {
		fmt.Fprintf(out, "\n%s\n", report.Selection.Summary)
	}
	fmt.Fprintf(out, "\n%s\n", report.Policy.Line())
	if report.ToolName != "" {
		fmt.Fprintf(out, "\n✓ %s detected: %s\n✓ Terraform project detected\n", report.ToolName, report.ToolVersion)
	}
	printProviders(out, report.Providers)
	printPlan(out, report.Changes)
	printAWSContext(out, report.AWSContext)
	visible := visibleFindings(report.Findings, options.All)
	printFindings(out, visible)
	printGaps(out, report.Findings)
	printCoverage(out, report)
	// The one summary: the same counts as the JSON document's.
	summary := report.Summary
	fmt.Fprintf(out, "\nPreflight: %s\n", summary.Verdict)
	fmt.Fprintf(out, "Findings: %d blocking, %s, %d informational\n", summary.Blocking, pluralize(summary.Warnings, "warning", "warnings"), summary.Informational)
	fmt.Fprintf(out, "Resources: %d checked, %d partial, %d not covered, %d unsupported\n", summary.Checked, summary.Partial, summary.NotCovered, summary.Unsupported)
	fmt.Fprintln(out, "No result guarantees terraform apply will succeed.")
	fmt.Fprintln(out, "Report a wrong result: https://github.com/tfpreflight/tfpreflight/issues/new?template=wrong-result.yml")
}

// visibleFindings are the findings listed one by one. Coverage notes never
// are: printGaps lists them a line per resource.
func visibleFindings(findings []model.Finding, showAll bool) []model.Finding {
	visible := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		if len(finding.Gaps) > 0 {
			continue
		}
		if showAll || finding.Confidence == model.ConfidenceHigh || (finding.Severity == model.SeverityWarning && finding.Confidence == model.ConfidenceMedium) {
			visible = append(visible, finding)
		}
	}
	return visible
}

// printGaps lists what the checks could not cover, one line per resource, then
// why each kind of gap happens, once.
func printGaps(out io.Writer, findings []model.Finding) {
	var resources []string
	summaries := map[string][]string{}
	var reasons []string
	for _, finding := range findings {
		for _, gap := range finding.Gaps {
			if _, listed := summaries[finding.Resource]; !listed {
				resources = append(resources, finding.Resource)
			}
			summaries[finding.Resource] = append(summaries[finding.Resource], gap.Summary)
			if !slices.Contains(reasons, gap.Why) {
				reasons = append(reasons, gap.Why)
			}
		}
	}
	if len(resources) == 0 {
		return
	}
	fmt.Fprintln(out, "\nNot checked (gaps in coverage, not predicted failures):")
	for _, resource := range resources {
		fmt.Fprintf(out, "  %s: %s\n", resource, strings.Join(summaries[resource], "; "))
	}
	fmt.Fprintln(out)
	for _, reason := range reasons {
		fmt.Fprintf(out, "  %s\n", reason)
	}
	fmt.Fprintln(out, "  Confirm these another way, such as a dry run in a non-production account.")
}

func printProviders(out io.Writer, providers []model.Provider) {
	fmt.Fprintln(out, "\nProviders:")
	for _, provider := range providers {
		fmt.Fprintf(out, "  %s\n", providerLabel(provider))
	}
}

func providerLabel(provider model.Provider) string {
	switch provider {
	case model.ProviderAWS:
		return "AWS"
	case model.ProviderAzure:
		return "Azure"
	case model.ProviderGCP:
		return "GCP"
	case model.ProviderKubernetes:
		return "Kubernetes"
	default:
		return "Unknown"
	}
}

func printPlan(out io.Writer, changes []model.PlannedChange) {
	counts := map[model.Action]int{}
	for _, change := range changes {
		counts[change.Action]++
	}
	fmt.Fprintln(out, "\nPlan:")
	if counts[model.ActionCreate] > 0 {
		fmt.Fprintf(out, "  + %d create\n", counts[model.ActionCreate])
	}
	if counts[model.ActionUpdate] > 0 {
		fmt.Fprintf(out, "  ~ %d update\n", counts[model.ActionUpdate])
	}
	if counts[model.ActionDelete] > 0 {
		fmt.Fprintf(out, "  - %d destroy\n", counts[model.ActionDelete])
	}
	if counts[model.ActionReplace] > 0 {
		fmt.Fprintf(out, "  ± %d replace\n", counts[model.ActionReplace])
	}
}

func printAWSContext(out io.Writer, context model.AWSContext) {
	if context.InspectionIdentity == "" && context.ApplyIdentity == "" && context.Region == "" && context.Unresolved == "" {
		return
	}
	fmt.Fprintln(out, "\nAWS context")
	if line := RegionLine(context); line != "" {
		fmt.Fprintf(out, "\n%s\n", line)
	}
	if context.InspectionIdentity != "" {
		fmt.Fprintf(out, "\nInspection identity:\n%s\n", indent(context.InspectionIdentity))
	} else {
		fmt.Fprintln(out, "\nInspection identity:\n      unavailable")
	}
	if context.AssumedRole != "" {
		fmt.Fprintf(out, "      inspection checks assumed %s\n", context.AssumedRole)
	} else if context.InspectionUnavailable != "" {
		fmt.Fprintf(out, "      inspection checks partial: %s\n", friendlyAWSFailure(context.InspectionUnavailable))
	}
	fmt.Fprintln(out, "\nApply identity:")
	if context.ApplyIdentityKnown {
		fmt.Fprintln(out, indent(context.ApplyIdentity))
		if context.ApplyIdentitySource != "" {
			fmt.Fprintf(out, "      (from %s)\n", context.ApplyIdentitySource)
		}
	} else {
		fmt.Fprintln(out, "      could not be reliably determined")
	}
	if context.ApplyIdentityNote != "" {
		fmt.Fprintf(out, "      %s\n", context.ApplyIdentityNote)
	}
}

// RegionLine says which region the AWS checks inspected and where it came
// from, and why they did not run when they did not. The region can be known
// while the account is not.
func RegionLine(context model.AWSContext) string {
	region := "Region: unresolved"
	if context.Region != "" {
		region = fmt.Sprintf("Region: %s (from %s)", context.Region, context.RegionSource)
	}
	switch {
	case context.Unresolved != "":
		return region + "\nAWS checks did not run: " + context.Unresolved
	case context.Region != "":
		return region
	default:
		return ""
	}
}

func printFindings(out io.Writer, findings []model.Finding) {
	if len(findings) == 0 {
		fmt.Fprintln(out, "\nNo findings to show.")
		return
	}

	fmt.Fprintln(out, "\nPreflight findings")
	for _, finding := range findings {
		label := severityLabel(finding.Severity)
		if finding.Severity == model.SeverityError && !isBlocking(finding) {
			label = "WARN"
		}
		fmt.Fprintf(out, "\n%s  %s\n", label, finding.Resource)
		fmt.Fprintf(out, "      %s\n", finding.Title)
		printExplanation(out, finding)
		if finding.Reason != "" {
			fmt.Fprintf(out, "\n      %s\n", finding.Reason)
		}
	}
}

func printCoverage(out io.Writer, report Report) {
	coverage := report.Coverage
	if len(coverage.Resources) == 0 {
		return
	}
	stats := summarizeCoverage(coverage)
	fmt.Fprintln(out, "\nCoverage")
	table := coverageTable(out)
	fmt.Fprintf(table, "AWS resources:\t%d\n", len(coverage.Resources))
	fmt.Fprintf(table, "Resources with verified rules:\t%d\n", stats.verified)
	fmt.Fprintf(table, "Resources with generated rules:\t%d\n", stats.generated)
	_ = table.Flush()
	fmt.Fprintln(out, "\nResources per check:")
	table = coverageTable(out)
	fmt.Fprintf(table, "Permissions:\t%s\n", permissionLine(stats))
	fmt.Fprintf(table, "Conflicts:\t%s\n", coverageLine(stats.conflictStatuses))
	fmt.Fprintf(table, "Quota:\t%s\n", quotaLine(stats.quotaStatuses))
	if len(stats.dependencyStatuses) > 0 {
		line := fmt.Sprintf("%d checked, %d partial, %d no additional rule discovered, %d unsupported", stats.dependencyStatuses[model.CheckChecked], stats.dependencyStatuses[model.CheckPartialDependency], stats.dependencyStatuses[model.CheckNoDependencyRule], stats.dependencyStatuses[model.CheckUnsupported])
		if report.AWSContext.Unresolved != "" {
			line += " (from the plan only)"
		}
		fmt.Fprintf(table, "Dependencies:\t%s\n", line)
	}
	_ = table.Flush()
}

// coverageTable aligns one block of the coverage summary. Both blocks share
// the label width, so their values line up.
func coverageTable(out io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(out, len("Resources with generated rules:")+2, 0, 2, ' ', 0)
}

// permissionLine counts resources by permission result. Operations are
// named only when some were left uncovered.
func permissionLine(stats coverageStats) string {
	if stats.permissionChecked+stats.permissionPartial+stats.permissionSkipped == 0 {
		return "not applicable"
	}
	line := fmt.Sprintf("%d checked, %d partial", stats.permissionChecked, stats.permissionPartial)
	if stats.uncoveredOperations > 0 {
		line += " (" + pluralize(stats.uncoveredOperations, "API operation", "API operations") + " not covered)"
	}
	if stats.permissionSkipped > 0 {
		line += fmt.Sprintf(", %d skipped (apply identity unknown)", stats.permissionSkipped)
	}
	return line
}

// Verdict is the run's result in a few words: blocking findings first, then the
// failure policy, then what could not be checked. A run whose AWS checks did not
// run, got no answer from AWS, or verified nothing never reads as a pass, as
// with broken credentials in CI.
func (r Report) Verdict() string {
	if r.Summary.Blocking > 0 {
		return "FAILED"
	}
	if reason, _ := r.Failure(); reason != "" {
		return "FAILED (" + reason + ")"
	}
	if r.AWSContext.Unresolved != "" {
		return "PARTIAL - AWS checks did not run: " + r.AWSContext.Unresolved
	}
	unanswered := len(r.Coverage.Resources) > 0 && !r.awsAnswered()
	if reason := r.mainAWSFailure(); unanswered && reason != "" {
		return "PARTIAL - AWS checks failed: " + reason
	}
	if !summarizeCoverage(r.Coverage).anyChecked() {
		return "PARTIAL - nothing was verified"
	}
	if unanswered {
		// Only checks that read the plan finished.
		return "PARTIAL - nothing was checked in AWS"
	}
	if r.Summary.Partial > 0 || r.Summary.NotCovered > 0 || r.Summary.Unsupported > 0 {
		return "PASSED (PARTIAL)"
	}
	return "COMPLETE"
}

// awsAnswered reports whether AWS answered any check. A permission, conflict or
// quota check is checked only on AWS's answer. AWSAnswers counts the rest:
// permissions IAM answered but left partial, and dependency lookups, since a
// dependency check can pass on the plan alone.
func (r Report) awsAnswered() bool {
	if r.Coverage.AWSAnswers > 0 {
		return true
	}
	for _, resource := range r.Coverage.Resources {
		if resource.Permissions == model.CheckChecked || resource.Conflicts == model.CheckChecked || resource.Quota == model.CheckChecked {
			return true
		}
	}
	return false
}

// mainAWSFailure is the commonest reason an AWS call got no answer, or "".
func (r Report) mainAWSFailure() string {
	counts := map[string]int{}
	add := func(reason string) {
		if reason != "" {
			counts[reason]++
		}
	}
	for _, finding := range r.Findings {
		add(finding.AWSError)
	}
	for _, reason := range r.Coverage.AWSFailures {
		add(reason)
	}
	add(r.AWSContext.InspectionUnavailable)
	main := ""
	for reason, count := range counts {
		if count > counts[main] || count == counts[main] && reason < main {
			main = reason
		}
	}
	if main == "" {
		return ""
	}
	return friendlyAWSFailure(main)
}

var httpStatus = regexp.MustCompile(`(?i)\bHTTP\s+[1-5][0-9]{2}\b`)

// friendlyAWSFailure turns an SDK or transport error into the short reason a
// person needs in the verdict. The original error stays in diagnostics, which
// the CLI prints only with --debug.
func friendlyAWSFailure(reason string) string {
	lower := strings.ToLower(reason)
	switch {
	case lower == "":
		return "AWS returned an unexpected error"
	case strings.Contains(lower, "no aws credentials") || strings.Contains(lower, "no credential providers"):
		return "no AWS credentials were found"
	case strings.Contains(lower, "expiredtoken") || strings.Contains(lower, "expired token") || strings.Contains(lower, "requestexpired"):
		return "AWS credentials have expired"
	case strings.Contains(lower, "accessdenied"), strings.Contains(lower, "access denied"), strings.Contains(lower, "unauthorized"), strings.Contains(lower, "forbidden"):
		return "AWS denied the inspection role access"
	case strings.Contains(lower, "timeout"), strings.Contains(lower, "deadline exceeded"), strings.Contains(lower, "connection refused"), strings.Contains(lower, "no such host"), strings.Contains(lower, "network is unreachable"), strings.Contains(lower, "dial tcp"):
		return "AWS could not be reached"
	case httpStatus.MatchString(reason):
		return "AWS returned an unexpected HTTP error"
	default:
		return "AWS returned an unexpected error"
	}
}

type coverageStats struct {
	verified            int
	generated           int
	permissionChecked   int
	permissionPartial   int
	permissionSkipped   int
	uncoveredOperations int
	conflictStatuses    map[model.CheckStatus]int
	quotaStatuses       map[model.CheckStatus]int
	dependencyStatuses  map[model.CheckStatus]int
}

func (s coverageStats) anyChecked() bool {
	return s.permissionChecked > 0 || s.conflictStatuses[model.CheckChecked] > 0 ||
		s.quotaStatuses[model.CheckChecked] > 0 || s.dependencyStatuses[model.CheckChecked] > 0
}

func summarizeCoverage(coverage model.Coverage) coverageStats {
	stats := coverageStats{dependencyStatuses: map[model.CheckStatus]int{}, conflictStatuses: map[model.CheckStatus]int{}, quotaStatuses: map[model.CheckStatus]int{}}
	for _, resource := range coverage.Resources {
		if resource.Dependencies != "" {
			stats.dependencyStatuses[resource.Dependencies]++
		}
		switch resource.Trust {
		case "generated":
			stats.generated++
		case "verified":
			stats.verified++
		}
		if resource.Permissions == model.CheckChecked {
			stats.permissionChecked++
		}
		if resource.Permissions == model.CheckSkipped {
			stats.permissionSkipped++
		}
		if resource.Permissions.IsPartial() {
			stats.permissionPartial++
			stats.uncoveredOperations += len(resource.PartialReasons())
		}
		stats.conflictStatuses[resource.Conflicts]++
		stats.quotaStatuses[resource.Quota]++
	}
	return stats
}

// coverageLine counts resources by one check's result. "not applicable"
// means the check applied to no resource; one that ran and could not finish
// is partial.
func coverageLine(statuses map[model.CheckStatus]int) string {
	checked, partial, unsupported := coverageCounts(statuses)
	if checked+partial+unsupported == 0 {
		return "not applicable"
	}
	return fmt.Sprintf("%d checked, %d partial, %d unsupported", checked, partial, unsupported)
}

// coverageCounts counts resources by one check's result.
func coverageCounts(statuses map[model.CheckStatus]int) (checked, partial, unsupported int) {
	for status, count := range statuses {
		switch {
		case status == model.CheckChecked:
			checked += count
		case status.IsPartial() || status == model.CheckUnverifiable:
			partial += count
		case status == model.CheckUnsupported:
			unsupported += count
		}
	}
	return checked, partial, unsupported
}

// quotaLine is coverageLine with the resources whose type has no known quota
// counted on their own, as the dependency line counts those with no rule.
func quotaLine(statuses map[model.CheckStatus]int) string {
	noRule := statuses[model.CheckNoQuotaRule]
	if noRule == 0 {
		return coverageLine(statuses)
	}
	checked, partial, unsupported := coverageCounts(statuses)
	return fmt.Sprintf("%d checked, %d partial, %d no quota rule, %d unsupported", checked, partial, noRule, unsupported)
}

func printExplanation(out io.Writer, finding model.Finding) {
	for _, section := range explanationSections(finding) {
		switch {
		case section.text == "":
		case section.inline:
			fmt.Fprintf(out, "\n      %s: %s\n", section.heading, section.text)
		default:
			fmt.Fprintf(out, "\n      %s:\n%s\n", section.heading, section.text)
		}
	}
}

// explanationSection is one part of a finding's explanation: a heading and its
// text, on the same line when inline. Empty text leaves the section out.
type explanationSection struct {
	heading string
	text    string
	inline  bool
}

func explanationSections(finding model.Finding) []explanationSection {
	sections := []explanationSection{
		{heading: "Terraform is trying to", text: indentIfSet(finding.Operation)},
		{heading: "Problem", text: lineIfSet(finding.Problem)},
	}
	for _, detail := range finding.Details {
		sections = append(sections, explanationSection{heading: detail.Label, text: indent(detail.Value)})
	}
	decision := lineIfSet(finding.Decision)
	if decision != "" && finding.DecisionExplanation != "" {
		decision += "\n      " + finding.DecisionExplanation
	}
	sections = append(sections,
		explanationSection{heading: "Apply identity", text: lineIfSet(finding.Principal)},
		explanationSection{heading: "AWS decision", text: decision},
		explanationSection{heading: "What this means", text: lineIfSet(finding.Explanation)},
		explanationSection{heading: "Fix", text: lineIfSet(finding.Remediation)},
		explanationSection{heading: "Confidence", text: strings.ToUpper(string(finding.Confidence)), inline: true},
	)
	for _, note := range finding.Notes {
		if note == finding.AWSError {
			sections = append(sections, explanationSection{heading: "Note", text: indent(friendlyAWSFailure(note))})
			continue
		}
		sections = append(sections, explanationSection{heading: "Note", text: indent(note)})
	}
	return sections
}

func lineIfSet(value string) string {
	if value == "" {
		return ""
	}
	return "      " + value
}

func indentIfSet(value string) string {
	if value == "" {
		return ""
	}
	return indent(value)
}

func indent(value string) string {
	return "      " + strings.ReplaceAll(value, "\n", "\n      ")
}

func severityLabel(severity model.Severity) string {
	if severity == model.SeverityError {
		return "FAIL"
	}
	return strings.ToUpper(string(severity))
}

func pluralize(count int, singular, plural string) string {
	if count == 1 {
		return fmt.Sprintf("%d %s", count, singular)
	}
	return fmt.Sprintf("%d %s", count, plural)
}
