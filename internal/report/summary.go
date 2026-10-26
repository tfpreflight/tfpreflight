package report

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

// detailsHint points to the full output, which says what each short line
// leaves out.
const detailsHint = "Details: tfpreflight check --details"

// renderSummary writes the default text output: a one-line header, each
// blocking finding and warning in three lines, and the result in one or two
// lines. Informational findings, identities and coverage are in --details, and
// the result line says when anything could not be checked.
func renderSummary(out io.Writer, report Report) {
	fmt.Fprintln(out, header(report))
	if line := rulesLine(report.Selection); line != "" {
		fmt.Fprintln(out, line)
	}
	// What fails the apply first, then what to check; each in address order.
	for _, wanted := range []string{"FAIL", "WARN"} {
		for _, finding := range report.Findings {
			if summaryLabel(finding) != wanted {
				continue
			}
			fmt.Fprintf(out, "\n%s  %s\n", wanted, summaryAddress(finding))
			fmt.Fprintf(out, "      %s\n", withoutARNs(summaryBrief(finding)))
			if finding.Next != "" {
				fmt.Fprintf(out, "      %s\n", withoutARNs(finding.Next))
			}
		}
	}
	fmt.Fprintln(out)
	for _, line := range resultLines(report) {
		fmt.Fprintln(out, line)
	}
}

// header is the run in one line: the AWS provider version, the region and how
// many resources the plan changes.
func header(report Report) string {
	parts := []string{"tfpreflight"}
	aws := report.ProviderVersion != "" || len(report.Coverage.Resources) > 0 || report.AWSContext.Unresolved != ""
	if report.ProviderVersion != "" {
		parts = append(parts, "AWS provider "+report.ProviderVersion)
	}
	if aws {
		region := report.AWSContext.Region
		if region == "" {
			region = "region unknown"
		}
		parts = append(parts, region)
	}
	parts = append(parts, pluralize(resourceCount(report), "resource", "resources"))
	return strings.Join(parts, " · ")
}

// resourceCount is the AWS resources the checks covered, or every planned
// change when no AWS resource is in the plan.
func resourceCount(report Report) int {
	if count := len(report.Coverage.Resources); count > 0 {
		return count
	}
	return len(report.Changes)
}

// rulesLine says when the rules are not built for the project's provider
// version, so nothing can block.
func rulesLine(selection ProviderSelection) string {
	switch selection.Mode {
	case "NEWER":
		return fmt.Sprintf("Rules for %s are newest; results are warnings only. Run: tfpreflight update", selection.RulesVersion)
	case "OLDER":
		return fmt.Sprintf("Rules for %s are oldest; results are warnings only.", selection.RulesVersion)
	case "GAP":
		return fmt.Sprintf("Rules for %s are the nearest; results are warnings only. Run: tfpreflight update", selection.RulesVersion)
	default:
		return ""
	}
}

// summaryLabel is FAIL for a blocking finding and WARN for a warning; other
// findings are not listed.
func summaryLabel(finding model.Finding) string {
	switch {
	case len(finding.Gaps) > 0:
		return ""
	case isBlocking(finding):
		return "FAIL"
	case isWarning(finding):
		return "WARN"
	default:
		return ""
	}
}

// summaryAddress is the resource a finding is about; a finding about the whole
// run names the provider.
func summaryAddress(finding model.Finding) string {
	if finding.Resource == "" {
		return "AWS provider"
	}
	return finding.Resource
}

func summaryBrief(finding model.Finding) string {
	if finding.Brief != "" {
		return finding.Brief
	}
	return finding.Title
}

var arnPattern = regexp.MustCompile(`arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:[0-9]*:([^\s",;]+)`)

// withoutARNs keeps only the resource part of every ARN, so the default output
// never names an account.
func withoutARNs(text string) string {
	return arnPattern.ReplaceAllString(text, "$1")
}

// resultLines is the result: what fails the apply or why nothing could be
// checked, then how much was checked, then why the run exits 1 when only the
// failure policy makes it.
func resultLines(report Report) []string {
	summary := report.Summary
	warnings := ""
	if summary.Warnings > 0 {
		warnings = " " + pluralize(summary.Warnings, "warning", "warnings") + "."
	}
	var lines []string
	switch verdict := summary.Verdict; {
	case summary.Blocking > 0:
		lines = append(lines,
			"✗ "+pluralize(summary.Blocking, "problem", "problems")+" will likely make apply fail."+warnings,
			"  "+checkedLine(report)+" "+detailsHint)
	case report.AWSContext.Unresolved != "":
		reason, advice := notRun(report.AWSContext.Unresolved)
		lines = append(lines, "! AWS checks did not run: "+reason+"."+warnings, "  Only the plan was checked. "+advice)
	case strings.HasPrefix(verdict, "PARTIAL - AWS checks failed: "):
		lines = append(lines, "! AWS checks failed: "+strings.TrimPrefix(verdict, "PARTIAL - AWS checks failed: ")+"."+warnings,
			"  Only the plan was checked. "+detailsHint)
	case verdict == "PARTIAL - nothing was checked in AWS":
		lines = append(lines, "! Nothing was checked in AWS."+warnings, "  Only the plan was checked. "+detailsHint)
	case verdict == "PARTIAL - nothing was verified":
		lines = append(lines, "! Nothing could be checked."+warnings, "  "+detailsHint)
	case summary.Warnings > 0:
		lines = append(lines, "! "+pluralize(summary.Warnings, "warning", "warnings")+" to check. Nothing found that is sure to make apply fail.",
			"  "+checkedLine(report)+" "+detailsHint)
	default:
		lines = append(lines, "✓ No problems found. "+checkedLine(report))
		if unchecked := len(report.Coverage.Resources) - summary.Checked; unchecked > 0 {
			lines = append(lines, fmt.Sprintf("  %d could not be fully checked. %s", unchecked, detailsHint))
		}
	}
	switch _, classification := report.Failure(); classification {
	case "warnings":
		lines = append(lines, "  Exits 1 because --fail-on warning is set.")
	case "partial":
		lines = append(lines, "  Exits 1 because --fail-on-partial is set.")
	}
	return lines
}

// checkedLine counts the resources every applicable check covered.
func checkedLine(report Report) string {
	total := len(report.Coverage.Resources)
	if total == 0 {
		return "No AWS resources to check."
	}
	return fmt.Sprintf("Checked %d of %s fully.", report.Summary.Checked, pluralize(total, "resource", "resources"))
}

// notRun shortens why the AWS checks did not run and says what to do about
// it.
func notRun(reason string) (short, advice string) {
	switch {
	case reason == "no AWS credentials found":
		return reason, "Log in to AWS and run again."
	case strings.HasPrefix(reason, "inspection account identity unavailable"):
		return "the AWS account could not be confirmed (" + friendlyAWSFailure(reason) + ")", "Check your AWS login and network, then run again."
	case strings.Contains(reason, "region"):
		short, _, _ = strings.Cut(reason, onlyPlainRegionsPrefix)
		return short, "Write the provider's region as plain text, or set AWS_REGION, then run again."
	default:
		return reason, detailsHint
	}
}

// onlyPlainRegionsPrefix starts the advice the AWS context adds to every
// unresolved provider region; notRun replaces it with its own.
const onlyPlainRegionsPrefix = "; only a literal"
