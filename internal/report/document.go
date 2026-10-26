package report

import (
	"encoding/json"
	"io"
	"sort"
	"strings"

	"github.com/tfpreflight/tfpreflight/rules"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// SchemaVersion is the major version of the public JSON document.
const SchemaVersion = "1"

// Input is what Normalize copies into a Report. It copies the slices, so
// renderers never change the checks' data.
type Input struct {
	ToolName          string
	ToolVersion       string
	ProviderVersion   string
	Selection         ProviderSelection
	SupportedVersions []string
	Providers         []model.Provider
	Changes           []model.PlannedChange
	Findings          []model.Finding
	AWSContext        model.AWSContext
	Coverage          model.Coverage
	Diagnostics       []string
	Policy            Policy
}

// Report is the result both renderers read.
type Report struct {
	Input
	publicFindings []Finding
	publicCoverage []ResourceCoverage
	Summary        Summary
}

// Document is the public JSON contract. It does not serialize internal
// structures.
type Document struct {
	SchemaVersion      string             `json:"schema_version"`
	Provider           ProviderInfo       `json:"provider"`
	Findings           []Finding          `json:"findings"`
	Coverage           []ResourceCoverage `json:"coverage"`
	AWSContext         *AWSContextInfo    `json:"aws_context,omitempty"`
	Policy             Policy             `json:"policy"`
	Summary            Summary            `json:"summary"`
	ExitClassification string             `json:"exit_classification"`
	Error              string             `json:"error,omitempty"`
}

// AWSContextInfo is the region every AWS check inspected and where it came from:
// "provider block", "var.<name>", "local.<name>" or "environment". When Unresolved is set, no
// AWS check ran and Region is empty.
type AWSContextInfo struct {
	Region       string `json:"region,omitempty"`
	RegionSource string `json:"region_source,omitempty"`
	Unresolved   string `json:"unresolved,omitempty"`
	// ApplyIdentity is the principal whose permissions were checked, and
	// ApplyIdentitySource where it came from: "--principal", "provider
	// assume_role", "inspection identity" or "inspection identity's role
	// session". ApplyIdentityNote says why it is unknown, or anything else to
	// know.
	ApplyIdentity       string `json:"apply_identity,omitempty"`
	ApplyIdentitySource string `json:"apply_identity_source,omitempty"`
	ApplyIdentityNote   string `json:"apply_identity_note,omitempty"`
	// AssumedRole is the provider's role the inspection checks assumed;
	// InspectionUnavailable why they could not.
	AssumedRole           string `json:"assumed_role,omitempty"`
	InspectionUnavailable string `json:"inspection_unavailable,omitempty"`
}

// ProviderSelection is how the AWS provider version was chosen and whose rules
// ran.
type ProviderSelection struct {
	// Mode is COVERED, NEWER, OLDER or GAP; empty when no AWS check ran.
	Mode         string
	RulesVersion string
	Source       string
	LockVersion  string
	// Summary is the line the text output leads with.
	Summary string
}

// ProviderInfo is the provider knowledge a check used.
type ProviderInfo struct {
	Name              string   `json:"name,omitempty"`
	Version           string   `json:"version,omitempty"`
	SupportedVersions []string `json:"supported_versions"`
	// Mode relates Version to the covered versions: COVERED, NEWER, OLDER or
	// GAP. Outside COVERED nothing blocks.
	Mode string `json:"mode,omitempty"`
	// RulesVersion is the covered version whose rules ran.
	RulesVersion string `json:"rules_version,omitempty"`
	// VersionSource is where Version came from: flag, config or lock.
	VersionSource string `json:"version_source,omitempty"`
	// LockVersion is the version .terraform.lock.hcl selects, when known.
	LockVersion string `json:"lock_version,omitempty"`
}

// Finding is a finding as the JSON document shows it.
type Finding struct {
	ID         string           `json:"id"`
	Resource   string           `json:"resource"`
	Category   string           `json:"category"`
	Severity   model.Severity   `json:"severity"`
	Confidence model.Confidence `json:"confidence"`
	Blocking   bool             `json:"blocking"`
	Message    string           `json:"message"`
	Reason     string           `json:"reason,omitempty"`
}

// ResourceCoverage is which checks ran for one planned resource.
type ResourceCoverage struct {
	Resource string                       `json:"resource"`
	Status   string                       `json:"status"`
	Checks   map[string]model.CheckStatus `json:"checks"`
	Reasons  []string                     `json:"reasons"`
}

// Summary is the finding and coverage totals, and the verdict the text output
// ends with. The text output prints these same counts.
type Summary struct {
	// Verdict is the result in a few words, such as "FAILED" or "PARTIAL -
	// nothing was verified"; empty when the run failed with a tool error.
	Verdict     string `json:"verdict,omitempty"`
	Blocking    int    `json:"blocking"`
	NonBlocking int    `json:"non_blocking"`
	// NonBlocking findings are Warnings or Informational.
	Warnings      int `json:"warnings"`
	Informational int `json:"informational"`
	Checked       int `json:"checked"`
	Partial       int `json:"partial"`
	NotCovered    int `json:"not_covered"`
	Unsupported   int `json:"unsupported"`
}

// Normalize orders the input and computes the summary every renderer uses.
func Normalize(input Input) Report {
	report := Report{
		Input: Input{
			ToolName: input.ToolName, ToolVersion: input.ToolVersion,
			ProviderVersion:   input.ProviderVersion,
			Selection:         input.Selection,
			SupportedVersions: append([]string(nil), input.SupportedVersions...),
			Providers:         append([]model.Provider(nil), input.Providers...),
			Changes:           append([]model.PlannedChange(nil), input.Changes...),
			Findings:          stableFindings(input.Findings), AWSContext: input.AWSContext,
			Coverage:    stableCoverage(input.Coverage),
			Diagnostics: append([]string(nil), input.Diagnostics...),
			Policy:      input.Policy.normal(),
		},
		publicFindings: []Finding{}, publicCoverage: []ResourceCoverage{},
	}
	rules.SortVersions(report.SupportedVersions)
	sort.Slice(report.Providers, func(i, j int) bool { return report.Providers[i] < report.Providers[j] })
	sort.Strings(report.Diagnostics)

	for _, finding := range report.Findings {
		public := publicFinding(finding)
		report.publicFindings = append(report.publicFindings, public)
		if public.Blocking {
			report.Summary.Blocking++
		} else {
			report.Summary.NonBlocking++
		}
		switch {
		case isWarning(finding):
			report.Summary.Warnings++
		case !public.Blocking:
			report.Summary.Informational++
		}
	}
	for _, coverage := range report.Coverage.Resources {
		public := publicResourceCoverage(coverage, report.Diagnostics)
		report.publicCoverage = append(report.publicCoverage, public)
		switch public.Status {
		case "checked":
			report.Summary.Checked++
		case "partial":
			report.Summary.Partial++
		case "unsupported":
			report.Summary.Unsupported++
		default:
			report.Summary.NotCovered++
		}
	}
	report.Summary.Verdict = report.Verdict()
	return report
}

// Document returns the JSON document for a completed or failed run.
func (r Report) Document(toolError error) Document {
	document := Document{
		SchemaVersion: SchemaVersion,
		Provider: ProviderInfo{
			Version: r.ProviderVersion, SupportedVersions: append([]string(nil), r.SupportedVersions...),
			Mode: r.Selection.Mode, RulesVersion: r.Selection.RulesVersion, VersionSource: r.Selection.Source, LockVersion: r.Selection.LockVersion,
		},
		Findings: append([]Finding(nil), r.publicFindings...),
		Coverage: append([]ResourceCoverage(nil), r.publicCoverage...),
		Policy:   r.Policy.normal(),
		Summary:  r.Summary, ExitClassification: "completed",
	}
	if r.ProviderVersion != "" || len(r.Coverage.Resources) > 0 {
		document.Provider.Name = "aws"
	}
	document.AWSContext = awsContextInfo(r.AWSContext)
	if _, classification := r.Failure(); classification != "" {
		document.ExitClassification = classification
	}
	if toolError != nil {
		document.Summary.Verdict = ""
		document.ExitClassification = "tool_error"
		document.Error = toolError.Error()
	}
	return document
}

// awsContextInfo is the run's AWS context as the document shows it, or nil when
// there is nothing to show.
func awsContextInfo(context model.AWSContext) *AWSContextInfo {
	hasScope := context.Region != "" || context.Unresolved != ""
	hasIdentity := context.ApplyIdentitySource != "" || context.ApplyIdentityNote != "" || context.InspectionUnavailable != ""
	if !hasScope && !hasIdentity {
		return nil
	}
	info := &AWSContextInfo{}
	if hasScope {
		info.Unresolved = context.Unresolved
		if context.Unresolved == "" {
			info.Region, info.RegionSource = context.Region, context.RegionSource
		}
	}
	if hasIdentity {
		if context.ApplyIdentityKnown {
			info.ApplyIdentity, info.ApplyIdentitySource = context.ApplyIdentity, context.ApplyIdentitySource
		}
		info.ApplyIdentityNote, info.AssumedRole = context.ApplyIdentityNote, context.AssumedRole
		if context.InspectionUnavailable != "" {
			info.InspectionUnavailable = friendlyAWSFailure(context.InspectionUnavailable)
		}
	}
	return info
}

// WriteJSON writes one indented JSON document and a newline.
func WriteJSON(out io.Writer, document Document) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}

func isBlocking(finding model.Finding) bool {
	return finding.Severity == model.SeverityError && finding.Confidence == model.ConfidenceHigh
}

func publicFinding(finding model.Finding) Finding {
	reason := finding.Reason
	if reason == "" {
		reason = finding.Problem
	}
	if reason == "" {
		reason = finding.Explanation
	}
	return Finding{
		ID: finding.ID, Resource: finding.Resource, Category: finding.Category,
		Severity: finding.Severity, Confidence: finding.Confidence,
		Blocking: isBlocking(finding), Message: finding.Title, Reason: reason,
	}
}

func publicResourceCoverage(resource model.ResourceCoverage, diagnostics []string) ResourceCoverage {
	checks := map[string]model.CheckStatus{
		"permissions": resource.Permissions,
		"conflicts":   resource.Conflicts,
		"quota":       resource.Quota,
	}
	if resource.Dependencies != "" {
		checks["dependencies"] = resource.Dependencies
	}
	entry := ResourceCoverage{
		Resource: resource.Resource, Status: coverageStatus(checks), Checks: checks,
		Reasons: append([]string(nil), resource.PartialReasons()...),
	}
	if resource.PermissionsUnavailable != "" {
		entry.Reasons = append(entry.Reasons, friendlyAWSFailure(resource.PermissionsUnavailable))
	}
	if resource.UnresolvedAWSContext != "" {
		entry.Reasons = append(entry.Reasons, "aws context unresolved: "+resource.UnresolvedAWSContext)
	}
	prefix := resource.Resource + ": dependency "
	for _, diagnostic := range diagnostics {
		if strings.HasPrefix(diagnostic, prefix) {
			entry.Reasons = append(entry.Reasons, strings.TrimPrefix(diagnostic, prefix))
		}
	}
	sort.Strings(entry.Reasons)
	return entry
}

func coverageStatus(checks map[string]model.CheckStatus) string {
	checked, partial, unsupported, uncovered := 0, 0, 0, 0
	for _, status := range checks {
		switch {
		case status == model.CheckChecked:
			checked++
		case status.IsPartial() || status == model.CheckUnverifiable:
			partial++
		case status == model.CheckUnsupported:
			unsupported++
		// A dependency or quota check that found no rule had nothing to check,
		// as with a check that does not apply.
		case status == model.CheckNotApplicable, status == model.CheckNoDependencyRule, status == model.CheckNoQuotaRule:
		default:
			uncovered++
		}
	}
	switch {
	case partial > 0 || checked > 0 && unsupported+uncovered > 0:
		return "partial"
	case unsupported > 0:
		return "unsupported"
	case uncovered > 0 || checked == 0:
		return "not_covered"
	default:
		return "checked"
	}
}

func stableFindings(findings []model.Finding) []model.Finding {
	stable := append([]model.Finding(nil), findings...)
	for i := range stable {
		stable[i].Details = append([]model.Detail(nil), stable[i].Details...)
		sort.Slice(stable[i].Details, func(a, b int) bool {
			x, y := stable[i].Details[a], stable[i].Details[b]
			if x.Label != y.Label {
				return x.Label < y.Label
			}
			return x.Value < y.Value
		})
		stable[i].Notes = append([]string(nil), stable[i].Notes...)
		sort.Strings(stable[i].Notes)
	}
	sort.Slice(stable, func(i, j int) bool { return findingKey(stable[i]) < findingKey(stable[j]) })
	return stable
}

func findingKey(finding model.Finding) string {
	encoded, _ := json.Marshal(finding)
	return finding.Resource + "\x00" + finding.Category + "\x00" + string(encoded)
}

func stableCoverage(coverage model.Coverage) model.Coverage {
	coverage.Resources = append([]model.ResourceCoverage(nil), coverage.Resources...)
	for i := range coverage.Resources {
		resource := &coverage.Resources[i]
		resource.UnresolvedAuthorizationOperations = append([]string(nil), resource.UnresolvedAuthorizationOperations...)
		resource.UnevaluableConditionOperations = append([]string(nil), resource.UnevaluableConditionOperations...)
		sort.Strings(resource.UnresolvedAuthorizationOperations)
		sort.Strings(resource.UnevaluableConditionOperations)
	}
	sort.Slice(coverage.Resources, func(i, j int) bool {
		return coverage.Resources[i].Resource < coverage.Resources[j].Resource
	})
	return coverage
}
