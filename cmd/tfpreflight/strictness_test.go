package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/report"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

var (
	blockingFinding = model.Finding{ID: "aws.s3-bucket-conflict", Resource: "aws_s3_bucket.a", Severity: model.SeverityError, Confidence: model.ConfidenceHigh}
	warningFinding  = model.Finding{ID: "aws.identity-conflict", Resource: "aws_sqs_queue.b", Severity: model.SeverityWarning, Confidence: model.ConfidenceMedium}
	// A permission that may be denied: a check that could not complete,
	// informational, never a warning.
	partialFinding  = model.Finding{ID: "aws.permission-may-be-denied", Resource: "aws_lambda_function.c", Severity: model.SeverityInfo, Confidence: model.ConfidenceLow}
	partialCoverage = model.Coverage{Resources: []model.ResourceCoverage{{Resource: "aws_lambda_function.c", Permissions: model.CheckPartialSimulationUnavailable}}}
)

// Every combination of policy and result: blocking findings always fail; a
// warning fails only with --fail-on warning; a partial check only with
// --fail-on-partial; partial never counts as a warning.
func TestStrictnessCombinations(t *testing.T) {
	type result struct {
		name     string
		findings []model.Finding
		coverage model.Coverage
	}
	results := []result{
		{"clean", nil, model.Coverage{}},
		{"warning", []model.Finding{warningFinding}, model.Coverage{}},
		{"partial", []model.Finding{partialFinding}, partialCoverage},
		{"blocking", []model.Finding{blockingFinding}, model.Coverage{}},
	}
	policies := []report.Policy{
		{FailOn: report.FailOnError},
		{FailOn: report.FailOnWarning},
		{FailOn: report.FailOnError, FailOnPartial: true},
		{FailOn: report.FailOnWarning, FailOnPartial: true},
	}
	want := map[string][4]int{
		//          error warning error+partial warning+partial
		"clean":    {0, 0, 0, 0},
		"warning":  {0, 1, 0, 1},
		"partial":  {0, 0, 1, 1},
		"blocking": {1, 1, 1, 1},
	}
	for _, r := range results {
		for index, policy := range policies {
			outcome := checkOutcome{Report: report.Normalize(report.Input{Findings: r.findings, Coverage: r.coverage, Policy: policy})}
			if got := exitCode(outcome.commandError()); got != want[r.name][index] {
				t.Errorf("%s under %+v: exit %d, want %d", r.name, policy, got, want[r.name][index])
			}
		}
	}
}

// The active policy is in the text header and the JSON document, with the
// exit classification it produced.
func TestStrictnessIsReported(t *testing.T) {
	policy := report.Policy{FailOn: report.FailOnWarning, FailOnPartial: true, Source: "--fail-on, --fail-on-partial"}
	normalized := report.Normalize(report.Input{Findings: []model.Finding{warningFinding}, Policy: policy})
	var text, short bytes.Buffer
	report.Render(&text, normalized, report.Options{Details: true})
	if !strings.Contains(text.String(), "\nFails on: blocking findings, warnings, partial checks (from --fail-on, --fail-on-partial)\n") {
		t.Fatalf("header lacks the policy:\n%s", text.String())
	}
	report.Render(&short, normalized, report.Options{})
	if !strings.Contains(short.String(), "\n  Exits 1 because --fail-on warning is set.\n") {
		t.Fatalf("default output does not say why it exits 1:\n%s", short.String())
	}
	var out bytes.Buffer
	if err := report.WriteJSON(&out, normalized.Document(nil)); err != nil {
		t.Fatal(err)
	}
	var document struct {
		Policy             report.Policy `json:"policy"`
		ExitClassification string        `json:"exit_classification"`
		Summary            struct {
			Warnings int `json:"warnings"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(out.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document.Policy != policy || document.ExitClassification != "warnings" || document.Summary.Warnings != 1 {
		t.Fatalf("document = %+v", document)
	}
	defaultText := bytes.Buffer{}
	report.Render(&defaultText, report.Normalize(report.Input{}), report.Options{Details: true})
	if !strings.Contains(defaultText.String(), "\nFails on: blocking findings (from default)\n") {
		t.Fatalf("default header:\n%s", defaultText.String())
	}
}
