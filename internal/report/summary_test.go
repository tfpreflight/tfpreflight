package report

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

// sixResources is coverage for six planned AWS resources, the first checked
// of them fully checked and the rest partial.
func sixResources(checked int) model.Coverage {
	var coverage model.Coverage
	for i := range 6 {
		resource := model.ResourceCoverage{
			Resource: fmt.Sprintf("aws_s3_bucket.r%d", i), Permissions: model.CheckChecked,
			Conflicts: model.CheckNotApplicable, Quota: model.CheckNotApplicable,
		}
		if i >= checked {
			resource.Permissions = model.CheckPartialUnevaluableCondition
		}
		coverage.Resources = append(coverage.Resources, resource)
	}
	return coverage
}

// covered is the rules selection for 6.64.0, which the rules cover exactly.
var covered = ProviderSelection{Mode: "COVERED", RulesVersion: "6.64.0"}

var usEast1 = model.AWSContext{Region: "us-east-1", RegionSource: "var.region"}

// The default output for each situation in testdata/summary, byte for byte.
func TestSummaryGolden(t *testing.T) {
	bucketTaken := model.Finding{
		Resource: "aws_s3_bucket.logs", Severity: model.SeverityError, Confidence: model.ConfidenceHigh,
		Title: "Apply will likely fail", Brief: `Bucket name "acme-logs" is already taken.`, Next: "Fix: use a different name, or import the existing bucket.",
	}
	for name, input := range map[string]Input{
		"problems": {
			ProviderVersion: "6.64.0", Selection: covered, AWSContext: usEast1, Coverage: sixResources(4),
			Findings: []model.Finding{
				bucketTaken,
				{
					Resource: "aws_security_group.web", Severity: model.SeverityError, Confidence: model.ConfidenceHigh,
					Brief: "The apply role is not allowed to run ec2:CreateSecurityGroup.", Next: `Fix: remove or narrow the deny on role "deploy".`,
					Principal: "arn:aws:iam::123456789012:role/deploy",
				},
				// The text the 6.64.0 rules give for this change, pinned in the
				// permissions package's TestDocumentedWarningIsReal.
				{
					Resource: "aws_s3_bucket_public_access_block.logs", Severity: model.SeverityWarning, Confidence: model.ConfidenceMedium,
					Brief: "The apply role may not be allowed to run s3:PutBucketPublicAccessBlock.",
					Next:  "Check: this rule comes from the provider's source and is not yet verified against AWS.",
				},
				{Resource: "aws_s3_bucket_public_access_block.logs", Severity: model.SeverityInfo, Confidence: model.ConfidenceLow, Brief: "Not listed."},
			},
		},
		// The example in README.md: two resources whose dependency checks found
		// no rule, which leaves nothing unchecked.
		"readme": {
			ProviderVersion: "6.64.0", Selection: covered, Findings: []model.Finding{bucketTaken},
			AWSContext: model.AWSContext{Region: "eu-west-1", RegionSource: "provider block"},
			Coverage: model.Coverage{Resources: []model.ResourceCoverage{
				{Resource: "aws_s3_bucket.logs", Permissions: model.CheckChecked, Conflicts: model.CheckChecked, Quota: model.CheckNotApplicable, Dependencies: model.CheckNoDependencyRule},
				{Resource: "aws_s3_bucket_versioning.logs", Permissions: model.CheckChecked, Conflicts: model.CheckNotApplicable, Quota: model.CheckNotApplicable, Dependencies: model.CheckNoDependencyRule},
			}},
		},
		"clear":         {ProviderVersion: "6.64.0", Selection: covered, AWSContext: usEast1, Coverage: sixResources(6)},
		"clear-partial": {ProviderVersion: "6.64.0", Selection: covered, AWSContext: usEast1, Coverage: sixResources(4)},
		"no-aws": {
			ProviderVersion: "6.64.0", Selection: covered, Coverage: sixResources(0),
			AWSContext: model.AWSContext{Unresolved: "no AWS credentials found"},
		},
		"newer-rules": {
			ProviderVersion: "6.70.0", Selection: ProviderSelection{Mode: "NEWER", RulesVersion: "6.69.1"}, AWSContext: usEast1, Coverage: sixResources(6),
			Findings: []model.Finding{func() model.Finding { f := bucketTaken; f.Severity = model.SeverityWarning; return f }()},
		},
	} {
		t.Run(name, func(t *testing.T) {
			want, err := os.ReadFile(filepath.Join("testdata", "summary", name+".txt"))
			if err != nil {
				t.Fatal(err)
			}
			var got bytes.Buffer
			Render(&got, Normalize(input), Options{})
			if got.String() != string(want) {
				t.Errorf("default output differs from testdata/summary/%s.txt\ngot:\n%s\nwant:\n%s", name, got.String(), want)
			}
		})
	}
}

// --details and --all give the full output, which the default leaves out.
func TestDetailsGiveTheFullOutput(t *testing.T) {
	report := Normalize(Input{ProviderVersion: "6.64.0", AWSContext: usEast1, Coverage: sixResources(6)})
	for _, options := range []Options{{Details: true}, {All: true}} {
		var out bytes.Buffer
		Render(&out, report, options)
		if !strings.HasPrefix(out.String(), "tfpreflight\n") || !strings.Contains(out.String(), "\nPreflight: COMPLETE\n") {
			t.Errorf("%+v: not the full output:\n%s", options, out.String())
		}
	}
}

// The default output names no account or ARN, even when a finding's text
// does.
func TestSummaryLeavesOutARNs(t *testing.T) {
	report := Normalize(Input{
		AWSContext: usEast1, Coverage: sixResources(6),
		Findings: []model.Finding{{
			Resource: "aws_iam_role_policy_attachment.a", Severity: model.SeverityError, Confidence: model.ConfidenceHigh,
			Brief: `Role policy attachment with role = arn:aws:iam::123456789012:role/app already exists.`, Next: "Fix: change one of these values.",
		}},
	})
	var out bytes.Buffer
	Render(&out, report, Options{})
	if strings.Contains(out.String(), "arn:") || strings.Contains(out.String(), "123456789012") || !strings.Contains(out.String(), "role = role/app already exists.") {
		t.Errorf("default output:\n%s", out.String())
	}
}

// Why the run exits 1 when only the failure policy makes it.
func TestSummarySaysWhyPolicyFails(t *testing.T) {
	for policy, want := range map[Policy]string{
		{FailOn: FailOnWarning}: "  Exits 1 because --fail-on warning is set.\n",
		{FailOnPartial: true}:   "  Exits 1 because --fail-on-partial is set.\n",
	} {
		report := Normalize(Input{
			ProviderVersion: "6.64.0", AWSContext: usEast1, Coverage: sixResources(4), Policy: policy,
			Findings: []model.Finding{{Resource: "aws_s3_bucket.r0", Severity: model.SeverityWarning, Confidence: model.ConfidenceMedium, Brief: "B.", Next: "Check: c."}},
		})
		var out bytes.Buffer
		Render(&out, report, Options{})
		if !strings.HasSuffix(out.String(), want) {
			t.Errorf("%+v: output does not end %q:\n%s", policy, want, out.String())
		}
	}
}
