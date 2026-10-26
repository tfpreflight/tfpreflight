package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

func TestDependencyCoverageDoesNotClaimComplete(t *testing.T) {
	var output bytes.Buffer
	coverage := model.Coverage{Resources: []model.ResourceCoverage{
		{Resource: "aws_subnet.unknown", Trust: "verified", Permissions: model.CheckChecked, Conflicts: model.CheckNotApplicable, Quota: model.CheckNotApplicable, Dependencies: model.CheckPartialDependency},
		{Resource: "aws_vpc.unmodelled", Trust: "verified", Permissions: model.CheckChecked, Conflicts: model.CheckNotApplicable, Quota: model.CheckNotApplicable, Dependencies: model.CheckNoDependencyRule},
	}}
	report := Normalize(Input{Coverage: coverage})
	Render(&output, report, Options{Details: true})
	for _, want := range []string{row("Dependencies:", "0 checked, 1 partial, 1 no additional rule discovered, 0 unsupported"), "Preflight: PASSED (PARTIAL)"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %q: %s", want, output.String())
		}
	}
}

func TestDependencyCoverageNamesPlanOnlyChecks(t *testing.T) {
	var output bytes.Buffer
	coverage := model.Coverage{Resources: []model.ResourceCoverage{{
		Resource: "aws_subnet.existing", Trust: "verified", Dependencies: model.CheckChecked,
		Permissions: model.CheckPartialAWSContext, Conflicts: model.CheckPartialAWSContext, Quota: model.CheckPartialAWSContext,
	}}}
	report := Normalize(Input{Coverage: coverage, AWSContext: model.AWSContext{Unresolved: "no AWS credentials found"}})
	Render(&output, report, Options{Details: true})
	if want := row("Dependencies:", "1 checked, 0 partial, 0 no additional rule discovered, 0 unsupported (from the plan only)"); !strings.Contains(output.String(), want) {
		t.Fatalf("missing %q: %s", want, output.String())
	}
}

func TestFriendlyAWSFailure(t *testing.T) {
	for input, want := range map[string]string{
		"no AWS credentials found": "no AWS credentials were found",
		"ExpiredToken: The security token included in the request is expired": "AWS credentials have expired",
		"AccessDenied (HTTP 403)":                         "AWS denied the inspection role access",
		"dial tcp: lookup sts.amazonaws.com: i/o timeout": "AWS could not be reached",
		"iam:GetUser failed: HTTP 503, request ID abc":    "AWS returned an unexpected HTTP error",
	} {
		if got := friendlyAWSFailure(input); got != want {
			t.Errorf("friendlyAWSFailure(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRawAWSNoteIsNotShownInText(t *testing.T) {
	var output bytes.Buffer
	raw := "AccessDeniedException: request ID 123"
	report := Normalize(Input{Findings: []model.Finding{{
		Severity: model.SeverityInfo, Confidence: model.ConfidenceLow, Title: "AWS check could not be completed", Notes: []string{raw}, AWSError: raw,
	}}})
	Render(&output, report, Options{All: true})
	if strings.Contains(output.String(), raw) {
		t.Fatalf("raw AWS error leaked into text output: %s", output.String())
	}
	if !strings.Contains(output.String(), "AWS denied the inspection role access") {
		t.Fatalf("friendly AWS error missing: %s", output.String())
	}
}

func TestRenderPermissionExplanation(t *testing.T) {
	var output bytes.Buffer
	report := Normalize(Input{Providers: []model.Provider{model.ProviderAWS}, Findings: []model.Finding{{
		Resource:            "aws_s3_bucket.test",
		Severity:            model.SeverityError,
		Confidence:          model.ConfidenceHigh,
		Title:               "Apply will likely fail",
		Operation:           "Create an S3 bucket",
		Problem:             "The deployment role does not have s3:CreateBucket.",
		Principal:           "arn:aws:iam::123456789012:role/tfpreflight-test-role",
		Decision:            "implicitDeny",
		DecisionExplanation: "No policy currently allows this action.",
		Explanation:         "Terraform can generate this plan, but AWS will reject the bucket creation during terraform apply.",
		Remediation:         "Allow s3:CreateBucket for the deployment role.",
		Notes:               []string{"AWS simulation is missing context: aws:TokenIssueTime"},
	}}})
	Render(&output, report, Options{All: true})

	for _, want := range []string{
		"FAIL  aws_s3_bucket.test",
		"Terraform is trying to:",
		"Create an S3 bucket",
		"No policy currently allows this action.",
		"Confidence: HIGH",
		"AWS simulation is missing context: aws:TokenIssueTime",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("rendered output missing %q:\n%s", want, output.String())
		}
	}
}

func TestVisibleFindingsShowsInformationalOnlyWithAll(t *testing.T) {
	findings := []model.Finding{
		{Severity: model.SeverityInfo, Confidence: model.ConfidenceMedium},
		{Severity: model.SeverityError, Confidence: model.ConfidenceHigh},
	}
	if got := visibleFindings(findings, false); len(got) != 1 {
		t.Fatalf("normal output shows %d findings, want 1", len(got))
	}
	if got := visibleFindings(findings, true); len(got) != 2 {
		t.Fatalf("--all output shows %d findings, want 2", len(got))
	}
}

// The report says which region was inspected and where it came from, in text
// and in JSON, or why no region could be decided.
func TestRegionSourceIsReported(t *testing.T) {
	for name, tc := range map[string]struct {
		context  model.AWSContext
		line     string
		document *AWSContextInfo
	}{
		"variable": {
			model.AWSContext{Region: "eu-west-1", RegionSource: "var.region"},
			"Region: eu-west-1 (from var.region)", &AWSContextInfo{Region: "eu-west-1", RegionSource: "var.region"},
		},
		"environment": {
			model.AWSContext{Region: "us-east-1", RegionSource: "environment"},
			"Region: us-east-1 (from environment)", &AWSContextInfo{Region: "us-east-1", RegionSource: "environment"},
		},
		"unresolved": {
			model.AWSContext{Unresolved: "provider region is computed from local.region"},
			"Region: unresolved\nAWS checks did not run: provider region is computed from local.region", &AWSContextInfo{Unresolved: "provider region is computed from local.region"},
		},
		"region known, account not": {
			model.AWSContext{Region: "us-east-1", RegionSource: "provider block", Unresolved: "inspection account identity unavailable"},
			"Region: us-east-1 (from provider block)\nAWS checks did not run: inspection account identity unavailable", &AWSContextInfo{Unresolved: "inspection account identity unavailable"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			report := Normalize(Input{AWSContext: tc.context})
			var text bytes.Buffer
			Render(&text, report, Options{Details: true})
			if !strings.Contains(text.String(), "\n"+tc.line+"\n") {
				t.Fatalf("text output lacks %q:\n%s", tc.line, text.String())
			}
			var out bytes.Buffer
			if err := WriteJSON(&out, report.Document(nil)); err != nil {
				t.Fatal(err)
			}
			var decoded struct {
				AWSContext *AWSContextInfo `json:"aws_context"`
			}
			if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.AWSContext == nil || *decoded.AWSContext != *tc.document {
				t.Fatalf("aws_context = %+v, want %+v", decoded.AWSContext, tc.document)
			}
		})
	}
}

// A check that ran but could not finish is partial in the text summary, never
// "not applicable".
func TestCoverageSummaryCountsPartialChecks(t *testing.T) {
	coverage := model.Coverage{Resources: []model.ResourceCoverage{
		{Resource: "aws_iam_user.a", Permissions: model.CheckChecked, Conflicts: model.CheckUnverifiable, Quota: model.CheckNotApplicable},
		{Resource: "aws_iam_group.b", Permissions: model.CheckChecked, Conflicts: model.CheckChecked, Quota: model.CheckNotApplicable},
		{Resource: "aws_s3_bucket.c", Permissions: model.CheckChecked, Conflicts: model.CheckPartialAWSContext, Quota: model.CheckNotApplicable},
		{Resource: "aws_vpc.d", Permissions: model.CheckChecked, Conflicts: model.CheckUnsupported, Quota: model.CheckNotApplicable},
	}}
	var out bytes.Buffer
	Render(&out, Normalize(Input{Coverage: coverage}), Options{Details: true})
	for _, want := range []string{row("Conflicts:", "1 checked, 2 partial, 1 unsupported\n"), row("Quota:", "not applicable\n")} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("summary lacks %q:\n%s", want, out.String())
		}
	}
}

// The report says which identity permissions were checked for and where it
// came from, and whether the inspection checks could assume the provider's
// role, in text and in JSON.
func TestApplyIdentitySourceIsReported(t *testing.T) {
	role := "arn:aws:iam::123456789012:role/deploy"
	for name, tc := range map[string]struct {
		context  model.AWSContext
		lines    []string
		document AWSContextInfo
	}{
		"assume_role": {
			model.AWSContext{Region: "us-east-1", RegionSource: "provider block", ApplyIdentity: role, ApplyIdentityKnown: true, ApplyIdentitySource: "provider assume_role", AssumedRole: role},
			[]string{"inspection checks assumed " + role, role + "\n      (from provider assume_role)"},
			AWSContextInfo{Region: "us-east-1", RegionSource: "provider block", ApplyIdentity: role, ApplyIdentitySource: "provider assume_role", AssumedRole: role},
		},
		"assume failed": {
			model.AWSContext{Region: "us-east-1", RegionSource: "provider block", ApplyIdentity: role, ApplyIdentityKnown: true, ApplyIdentitySource: "provider assume_role", InspectionUnavailable: "could not assume " + role + ": AccessDenied"},
			[]string{"inspection checks partial: AWS denied the inspection role access"},
			AWSContextInfo{Region: "us-east-1", RegionSource: "provider block", ApplyIdentity: role, ApplyIdentitySource: "provider assume_role", InspectionUnavailable: "AWS denied the inspection role access"},
		},
		"unknown": {
			model.AWSContext{Region: "us-east-1", RegionSource: "provider block", ApplyIdentityNote: "pass --principal <role ARN> to check permissions"},
			[]string{"could not be reliably determined\n      pass --principal <role ARN> to check permissions"},
			AWSContextInfo{Region: "us-east-1", RegionSource: "provider block", ApplyIdentityNote: "pass --principal <role ARN> to check permissions"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			report := Normalize(Input{AWSContext: tc.context})
			var text bytes.Buffer
			Render(&text, report, Options{Details: true})
			for _, line := range tc.lines {
				if !strings.Contains(text.String(), line) {
					t.Fatalf("text output lacks %q:\n%s", line, text.String())
				}
			}
			var out bytes.Buffer
			if err := WriteJSON(&out, report.Document(nil)); err != nil {
				t.Fatal(err)
			}
			var decoded struct {
				AWSContext *AWSContextInfo `json:"aws_context"`
			}
			if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.AWSContext == nil || *decoded.AWSContext != tc.document {
				t.Fatalf("aws_context = %+v, want %+v", decoded.AWSContext, tc.document)
			}
		})
	}
}

// A run in which no check completed for any resource, or whose AWS checks did
// not run, does not say PASSED.
func TestNothingVerifiedIsNotAPass(t *testing.T) {
	partial := model.ResourceCoverage{Resource: "aws_s3_bucket.b", Trust: "verified", Permissions: model.CheckPartialAWSContext, Conflicts: model.CheckNotApplicable, Quota: model.CheckPartialAWSContext, Dependencies: model.CheckNoDependencyRule}
	for name, tc := range map[string]struct {
		resource         model.ResourceCoverage
		unresolved       string
		want, unexpected string
	}{
		"nothing checked": {partial, "", "Preflight: PARTIAL - nothing was verified", "PASSED"},
		"one check done":  {func() model.ResourceCoverage { r := partial; r.Quota = model.CheckChecked; return r }(), "", "Preflight: PASSED (PARTIAL)", "nothing was verified"},
		// Dependencies the plan itself satisfies are checked without AWS; that
		// is not a pass when the AWS checks never ran.
		"AWS checks skipped": {
			func() model.ResourceCoverage { r := partial; r.Dependencies = model.CheckChecked; return r }(), "no AWS credentials found",
			"Preflight: PARTIAL - AWS checks did not run: no AWS credentials found", "PASSED",
		},
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			report := Normalize(Input{Coverage: model.Coverage{Resources: []model.ResourceCoverage{tc.resource}}, AWSContext: model.AWSContext{Unresolved: tc.unresolved}})
			Render(&output, report, Options{Details: true})
			if !strings.Contains(output.String(), tc.want) || strings.Contains(output.String(), tc.unexpected) {
				t.Fatalf("want %q and not %q:\n%s", tc.want, tc.unexpected, output.String())
			}
		})
	}
}

// row is one line of the coverage table as rendered.
func row(label, value string) string { return fmt.Sprintf("%-33s%s", label, value) }

// Every value in the coverage summary starts in the same column, and no line
// ends in padding.
func TestCoverageColumnsLineUp(t *testing.T) {
	coverage := model.Coverage{Resources: []model.ResourceCoverage{
		{Resource: "aws_vpc.a", Trust: "generated", Permissions: model.CheckPartialAWSContext, Conflicts: model.CheckNotApplicable, Quota: model.CheckChecked, Dependencies: model.CheckChecked},
	}}
	var out bytes.Buffer
	Render(&out, Normalize(Input{Coverage: coverage}), Options{Details: true})
	text := out.String()
	block := text[strings.Index(text, "\nCoverage\n"):strings.Index(text, "\nPreflight:")]
	rows := 0
	for _, line := range strings.Split(block, "\n") {
		if strings.HasSuffix(line, " ") {
			t.Errorf("trailing space: %q", line)
		}
		label, _, found := strings.Cut(line, ":")
		if !found || strings.HasSuffix(line, ":") {
			continue
		}
		rows++
		if value := strings.TrimLeft(line[len(label)+1:], " "); len(line)-len(value) != 33 {
			t.Errorf("value of %q starts at column %d, want 33", label, len(line)-len(value))
		}
	}
	if rows != 7 {
		t.Fatalf("found %d table rows, want 7:\n%s", rows, block)
	}
}

// Operations are counted only when some were missed: a partial result with
// none listed does not claim "0 API operations were not covered".
func TestPermissionLineNamesOperationsOnlyWhenMissed(t *testing.T) {
	for name, tc := range map[string]struct {
		resource model.ResourceCoverage
		want     string
	}{
		"none missed": {model.ResourceCoverage{Permissions: model.CheckPartialAWSContext}, "0 checked, 1 partial\n"},
		"two missed":  {model.ResourceCoverage{Permissions: model.CheckPartialUnevaluableCondition, UnevaluableConditionOperations: []string{"ec2:A", "ec2:B"}}, "0 checked, 1 partial (2 API operations not covered)\n"},
		"skipped":     {model.ResourceCoverage{Permissions: model.CheckSkipped}, "0 checked, 0 partial, 1 skipped (apply identity unknown)\n"},
	} {
		t.Run(name, func(t *testing.T) {
			tc.resource.Resource, tc.resource.Conflicts, tc.resource.Quota = "aws_vpc.a", model.CheckNotApplicable, model.CheckNotApplicable
			var out bytes.Buffer
			Render(&out, Normalize(Input{Coverage: model.Coverage{Resources: []model.ResourceCoverage{tc.resource}}}), Options{Details: true})
			if want := row("Permissions:", tc.want); !strings.Contains(out.String(), want) {
				t.Fatalf("lacks %q:\n%s", want, out.String())
			}
		})
	}
}

// The text output's one summary has the JSON document's counts, whether or
// not --all shows the informational findings.
func TestTextCountsMatchJSON(t *testing.T) {
	report := Normalize(Input{Findings: []model.Finding{
		{ID: "info", Severity: model.SeverityInfo, Confidence: model.ConfidenceMedium},
		{ID: "warn", Severity: model.SeverityWarning, Confidence: model.ConfidenceMedium},
		{ID: "gap", Severity: model.SeverityInfo, Confidence: model.ConfidenceLow, Gaps: []model.Gap{{Summary: "may call ec2:A", Why: "May call: why."}}},
	}})
	summary := report.Document(nil).Summary
	if summary.Blocking != 0 || summary.Warnings != 1 || summary.Informational != 2 || summary.NonBlocking != 3 {
		t.Fatalf("JSON summary = %+v", summary)
	}
	for _, all := range []bool{false, true} {
		var out bytes.Buffer
		Render(&out, report, Options{All: all, Details: true})
		text := out.String()
		if want := "Findings: 0 blocking, 1 warning, 2 informational\n"; !strings.Contains(text, want) {
			t.Errorf("--all=%v: lacks %q:\n%s", all, want, text)
		}
		if strings.Count(text, "Preflight:") != 1 || strings.Contains(text, "findings complete") {
			t.Errorf("--all=%v: not exactly one summary:\n%s", all, text)
		}
	}
}

// When the account and region resolved but AWS answered nothing, the verdict
// says the AWS checks failed and why, even if a dependency the plan itself
// satisfies was checked. One AWS answer is enough to say PASSED (PARTIAL).
func TestUnansweredAWSIsNotAPass(t *testing.T) {
	const denied = "permission simulation unavailable: simulating s3:CreateBucket failed: AccessDenied (HTTP 403)"
	planOnly := model.ResourceCoverage{Resource: "aws_subnet.a", Trust: "generated", Permissions: model.CheckPartialSimulationUnavailable, Conflicts: model.CheckNotApplicable, Quota: model.CheckNotApplicable, Dependencies: model.CheckChecked}
	failed := []model.Finding{
		{ID: "aws.permission-simulation-unavailable", Resource: "aws_subnet.a", Severity: model.SeverityInfo, Confidence: model.ConfidenceLow, AWSError: denied},
		{ID: "aws.permission-simulation-unavailable", Resource: "aws_subnet.b", Severity: model.SeverityInfo, Confidence: model.ConfidenceLow, AWSError: denied},
		{ID: "aws.s3-bucket-verification-unavailable", Resource: "aws_s3_bucket.c", Severity: model.SeverityInfo, Confidence: model.ConfidenceLow, AWSError: "AWS returned HTTP 403 while checking the bucket."},
	}
	for name, tc := range map[string]struct {
		findings []model.Finding
		coverage model.Coverage
		want     string
	}{
		"every AWS call failed":     {failed, model.Coverage{Resources: []model.ResourceCoverage{planOnly}}, "PARTIAL - AWS checks failed: AWS denied the inspection role access"},
		"dependency lookups failed": {nil, model.Coverage{Resources: []model.ResourceCoverage{planOnly}, AWSFailures: []string{"DescribeVpcs: RequestTimeout"}}, "PARTIAL - AWS checks failed: AWS could not be reached"},
		"only the plan was read":    {nil, model.Coverage{Resources: []model.ResourceCoverage{planOnly}}, "PARTIAL - nothing was checked in AWS"},
		"IAM answered once":         {failed, model.Coverage{Resources: []model.ResourceCoverage{planOnly}, AWSAnswers: 1}, "PASSED (PARTIAL)"},
		"a conflict was checked": {failed, model.Coverage{Resources: []model.ResourceCoverage{func() model.ResourceCoverage {
			r := planOnly
			r.Conflicts = model.CheckChecked
			return r
		}()}}, "PASSED (PARTIAL)"},
	} {
		t.Run(name, func(t *testing.T) {
			report := Normalize(Input{Findings: tc.findings, Coverage: tc.coverage})
			if got := report.Document(nil).Summary.Verdict; got != tc.want {
				t.Fatalf("verdict = %q, want %q", got, tc.want)
			}
		})
	}
}

// The full output's quota line counts resources with no known quota on their
// own, so every resource is accounted for.
func TestQuotaLineCountsNoQuotaRule(t *testing.T) {
	coverage := model.Coverage{Resources: []model.ResourceCoverage{
		{Resource: "aws_vpc.a", Permissions: model.CheckChecked, Conflicts: model.CheckNotApplicable, Quota: model.CheckChecked},
		{Resource: "aws_s3_bucket.a", Permissions: model.CheckChecked, Conflicts: model.CheckNotApplicable, Quota: model.CheckNoQuotaRule},
		{Resource: "aws_s3_bucket.b", Permissions: model.CheckChecked, Conflicts: model.CheckNotApplicable, Quota: model.CheckNoQuotaRule},
	}}
	var out bytes.Buffer
	Render(&out, Normalize(Input{Coverage: coverage}), Options{Details: true})
	if want := "Quota:                           1 checked, 0 partial, 2 no quota rule, 0 unsupported\n"; !strings.Contains(out.String(), want) {
		t.Errorf("lacks %q:\n%s", want, out.String())
	}
	if !strings.Contains(out.String(), "\nResources: 3 checked, 0 partial, 0 not covered, 0 unsupported\n") {
		t.Errorf("resources not all fully checked:\n%s", out.String())
	}
}
