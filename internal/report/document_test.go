package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

func TestPublicDocumentStableAcrossEngineOrdering(t *testing.T) {
	findings := []model.Finding{{ID: "b", Resource: "aws_z.b", Category: "quota", Severity: model.SeverityWarning, Confidence: model.ConfidenceMedium, Title: "Warning"}, {ID: "a", Resource: "aws_a.a", Category: "dependency", Severity: model.SeverityWarning, Confidence: model.ConfidenceMedium, Title: "Missing"}}
	coverage := model.Coverage{Resources: []model.ResourceCoverage{{Resource: "aws_z.b", Permissions: model.CheckUnsupported, Conflicts: model.CheckNotApplicable, Quota: model.CheckNotApplicable}, {Resource: "aws_a.a", Permissions: model.CheckPartialUnresolvedAuthorization, Conflicts: model.CheckNotApplicable, Quota: model.CheckNotApplicable, UnresolvedAuthorizationOperations: []string{"z", "a"}}}}
	first := Normalize(Input{ProviderVersion: "6.64.0", SupportedVersions: []string{"6.64.0"}, Findings: findings, Coverage: coverage}).Document(nil)
	findings[0], findings[1] = findings[1], findings[0]
	coverage.Resources[0], coverage.Resources[1] = coverage.Resources[1], coverage.Resources[0]
	coverage.Resources[0].UnresolvedAuthorizationOperations = []string{"a", "z"}
	second := Normalize(Input{ProviderVersion: "6.64.0", SupportedVersions: []string{"6.64.0"}, Findings: findings, Coverage: coverage}).Document(nil)
	var a, b bytes.Buffer
	if err := WriteJSON(&a, first); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&b, second); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Fatal("JSON depends on engine iteration order")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(a.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"schema_version", "provider", "findings", "coverage", "summary", "exit_classification"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("public field renamed: %s", key)
		}
	}
	// Standard consumers tolerate additive fields without a schema-major change.
	fields["future_optional"] = json.RawMessage(`true`)
	data, _ := json.Marshal(fields)
	var decoded Document
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Summary.Partial != 1 || decoded.Summary.Unsupported != 1 || decoded.Summary.Blocking != 0 {
		t.Fatalf("incorrect summary %+v", decoded.Summary)
	}
}

func TestTerminalStableAndDoesNotMutate(t *testing.T) {
	f := []model.Finding{{Resource: "aws_b.b", Category: "dependency", Severity: model.SeverityWarning, Confidence: model.ConfidenceMedium, Notes: []string{"z", "a"}}, {Resource: "aws_a.a", Category: "permission", Severity: model.SeverityWarning, Confidence: model.ConfidenceMedium}}
	var a, b bytes.Buffer
	Render(&a, Normalize(Input{Findings: f}), Options{All: true})
	if f[0].Notes[0] != "z" {
		t.Fatal("rendering mutated engine findings")
	}
	f[0], f[1] = f[1], f[0]
	f[1].Notes = []string{"a", "z"}
	Render(&b, Normalize(Input{Findings: f}), Options{All: true})
	if a.String() != b.String() {
		t.Fatal("terminal ordering unstable")
	}
}

// A dependency or quota check that found no rule had nothing to check, so it
// leaves a resource fully checked; any check that did not finish still does
// not.
func TestNoDependencyRuleCountsAsNothingToCheck(t *testing.T) {
	for want, resource := range map[string]model.ResourceCoverage{
		"checked":                    {Permissions: model.CheckChecked, Conflicts: model.CheckChecked, Quota: model.CheckNotApplicable, Dependencies: model.CheckNoDependencyRule},
		"partial":                    {Permissions: model.CheckPartialUnevaluableCondition, Conflicts: model.CheckChecked, Quota: model.CheckNotApplicable, Dependencies: model.CheckNoDependencyRule},
		"checked with no quota rule": {Permissions: model.CheckChecked, Conflicts: model.CheckNotApplicable, Quota: model.CheckNoQuotaRule, Dependencies: model.CheckNoDependencyRule},
		"partial with no quota rule": {Permissions: model.CheckPartialSimulationUnavailable, Conflicts: model.CheckNotApplicable, Quota: model.CheckNoQuotaRule},
		// No check applied and none ran: nothing was covered.
		"not_covered": {Permissions: model.CheckNotApplicable, Conflicts: model.CheckNotApplicable, Quota: model.CheckNotApplicable, Dependencies: model.CheckNoDependencyRule},
	} {
		resource.Resource = "aws_s3_bucket.a"
		document := Normalize(Input{Coverage: model.Coverage{Resources: []model.ResourceCoverage{resource}}}).Document(nil)
		if got := document.Coverage[0].Status; got != strings.Fields(want)[0] {
			t.Errorf("%+v: status %q, want %q", resource, got, want)
		}
	}
}
