package check

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/plan"
	"github.com/tfpreflight/tfpreflight/internal/providerversion"
	"github.com/tfpreflight/tfpreflight/internal/report"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

var blockingFinding = model.Finding{ID: "aws.s3-bucket-conflict", Resource: "aws_s3_bucket.a", Severity: model.SeverityError, Confidence: model.ConfidenceHigh}

// Outside COVERED the default never blocks, but --fail-on warning still
// applies to what the nearest rules found.
func TestStrictnessOutsideCovered(t *testing.T) {
	newer := providerversion.Selection{Version: "6.70.0", Mode: providerversion.ModeNewer, RulesVersion: "6.69.1"}
	findings := applySelection(newer, []model.Finding{blockingFinding})
	for policy, want := range map[string]bool{report.FailOnError: false, report.FailOnWarning: true} {
		reason, _ := report.Normalize(report.Input{Findings: findings, Policy: report.Policy{FailOn: policy}}).Failure()
		if got := reason != ""; got != want {
			t.Errorf("--fail-on %s outside COVERED: fails %v, want %v", policy, got, want)
		}
	}
}

// A version other than the lock file's adds a warning whose brief names both.
func TestVersionMismatchBrief(t *testing.T) {
	selection := providerversion.Selection{Version: "6.64.0", Mode: providerversion.ModeCovered, RulesVersion: "6.64.0", LockVersion: "6.69.1", Source: "flag"}
	findings := applySelection(selection, nil)
	if len(findings) != 1 || findings[0].Brief != "These results are for AWS provider 6.64.0, but .terraform.lock.hcl selects 6.69.1." || findings[0].Next != "Fix: check against 6.69.1, or update the lock file." {
		t.Fatalf("findings = %+v", findings)
	}
}

// The policy comes from each flag, else .tfpreflight.yml, else the default.
func TestStrictnessSources(t *testing.T) {
	yes, no := true, false
	dir := t.TempDir()
	config := filepath.Join(dir, ".tfpreflight.yml")
	if err := os.WriteFile(config, []byte("fail_on: warning\nfail_on_partial: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		options Request
		path    string
		want    report.Policy
	}{
		"default":       {Request{}, filepath.Join(dir, "missing.yml"), report.Policy{FailOn: "error", Source: "default"}},
		"config":        {Request{}, config, report.Policy{FailOn: "warning", FailOnPartial: true, Source: ".tfpreflight.yml"}},
		"flags":         {Request{FailOn: "error", FailOnPartial: &no}, config, report.Policy{FailOn: "error", Source: "--fail-on, --fail-on-partial"}},
		"flag + config": {Request{FailOnPartial: &yes}, config, report.Policy{FailOn: "warning", FailOnPartial: true, Source: ".tfpreflight.yml, --fail-on-partial"}},
	} {
		t.Run(name, func(t *testing.T) {
			config, err := providerversion.ReadConfig(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			got, err := failurePolicy(tc.options, config)
			if err != nil || got != tc.want {
				t.Fatalf("policy = %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}
	if _, err := failurePolicy(Request{FailOn: "info"}, providerversion.Config{}); err == nil {
		t.Fatal("--fail-on info accepted")
	}
}

// An AWS provider configured from either registry needs the AWS checks, even
// when no resource change names it.
func TestRequiresAWSFromEitherRegistry(t *testing.T) {
	for registry, want := range map[string]bool{"registry.terraform.io": true, "registry.opentofu.org": true, "example.com/acme/cloud": false} {
		source := registry + "/hashicorp/aws"
		if !want {
			source = registry
		}
		plan := []byte(`{"configuration":{"provider_config":{"aws":{"full_name":"` + source + `"}}}}`)
		if got := requiresAWS(plan, nil); got != want {
			t.Errorf("%s: requiresAWS = %v, want %v", source, got, want)
		}
	}
}

// When the plan tfpreflight runs fails, as it does without credentials, the
// error says how to check a plan saved by hand instead.
func TestFailedPlanSuggestsASavedPlan(t *testing.T) {
	dir := t.TempDir()
	for kind, command := range map[plan.ToolKind]string{plan.Terraform: "terraform", plan.OpenTofu: "tofu"} {
		deps := Dependencies{
			Detect: func(context.Context, []plan.ToolKind) (plan.Tool, error) {
				return plan.Tool{Kind: kind, Name: string(kind)}, nil
			},
			Configuration: func(string) (bool, error) { return true, nil },
			Generate: func(context.Context, plan.Tool) (string, func(), error) {
				return "", func() {}, &plan.CommandError{Operation: "Terraform/OpenTofu plan", Diagnostics: "Error: No valid credential sources found"}
			},
			LockPath: filepath.Join(dir, "missing.lock.hcl"), ConfigPath: filepath.Join(dir, "missing.yml"),
		}
		_, err := Run(context.Background(), Request{}, deps)
		var failed *plan.CommandError
		if !errors.As(err, &failed) || !strings.Contains(err.Error(), command+" plan -out=tfplan\n  tfpreflight check --plan=tfplan") {
			t.Errorf("%s: error does not suggest a saved plan: %v", kind, err)
		}
	}
}
