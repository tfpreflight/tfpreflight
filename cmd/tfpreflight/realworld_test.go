package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/check"
	"github.com/tfpreflight/tfpreflight/internal/plan"
	"github.com/tfpreflight/tfpreflight/internal/report"
)

// maxRealWorldLines bounds the --details output for these plans: findings are
// listed one by one, coverage notes one line per resource. maxDefaultLines
// bounds the default output, which shows only what fails or warns.
const (
	maxRealWorldLines = 120
	maxDefaultLines   = 25
)

// The plans of five public terraform-aws-modules examples (testdata/realworld),
// checked where AWS cannot answer: with no credentials, with credentials whose
// every call fails, and with STS answering but every other call failing. None
// may crash, fail the run, claim a pass, or bury the reader, and the text and
// JSON must agree.
func TestRealWorldPlans(t *testing.T) {
	plans, err := filepath.Glob("testdata/realworld/*/plan.json")
	if err != nil || len(plans) != 5 {
		t.Fatalf("found %d real-world plans, want 5 (%v)", len(plans), err)
	}
	for _, path := range plans {
		dir, err := filepath.Abs(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		for mode, want := range map[string][2]string{
			"no credentials":  {"PARTIAL - AWS checks did not run: no AWS credentials found", "! AWS checks did not run: no AWS credentials found."},
			"AWS unreachable": {"PARTIAL - AWS checks did not run: inspection account identity unavailable: ", "! AWS checks did not run: the AWS account could not be confirmed ("},
			"AWS calls fail":  {"PARTIAL - AWS checks failed: ", "! AWS checks failed: "},
		} {
			t.Run(filepath.Base(dir)+"/"+mode, func(t *testing.T) {
				t.Chdir(dir)
				isolateAWS(t, mode != "no credentials")
				if mode == "AWS calls fail" {
					t.Setenv("AWS_ENDPOINT_URL_STS", fakeSTS(t))
				}
				summary, details, document := runRealWorldCheck(t)
				assertHonestResult(t, details, document, want[0])
				assertShortResult(t, summary, document, want[1])
			})
		}
	}
}

// isolateAWS leaves the AWS SDK nothing to find but, when withCredentials is
// set, static keys and an endpoint that refuses every connection.
func isolateAWS(t *testing.T, withCredentials bool) {
	t.Helper()
	missing := filepath.Join(t.TempDir(), "absent")
	for name, value := range map[string]string{
		"AWS_CONFIG_FILE": missing, "AWS_SHARED_CREDENTIALS_FILE": missing, "AWS_EC2_METADATA_DISABLED": "true",
		"AWS_ACCESS_KEY_ID": "", "AWS_SECRET_ACCESS_KEY": "", "AWS_SESSION_TOKEN": "", "AWS_PROFILE": "", "AWS_DEFAULT_PROFILE": "",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI": "", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "", "AWS_WEB_IDENTITY_TOKEN_FILE": "", "AWS_ROLE_ARN": "",
		"AWS_REGION": "", "AWS_DEFAULT_REGION": "", "AWS_ENDPOINT_URL": "", "AWS_ENDPOINT_URL_STS": "", "AWS_MAX_ATTEMPTS": "1",
	} {
		t.Setenv(name, value)
	}
	if withCredentials {
		t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
		t.Setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:1")
	}
}

// fakeSTS answers GetCallerIdentity, and only that, for an IAM user in the
// placeholder account.
func fakeSTS(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.PostForm.Get("Action") != "GetCallerIdentity" {
			http.Error(w, "unsupported", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult>`+
			`<Arn>arn:aws:iam::123456789012:user/example</Arn><UserId>AIDAEXAMPLE</UserId><Account>123456789012</Account>`+
			`</GetCallerIdentityResult><ResponseMetadata><RequestId>1</RequestId></ResponseMetadata></GetCallerIdentityResponse>`)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// runRealWorldCheck checks plan.json in the working directory as default text,
// as --details text and as JSON, with the real checks and Terraform replaced by
// the saved plan.
func runRealWorldCheck(t *testing.T) (summary, details string, document report.Document) {
	t.Helper()
	services := check.Production()
	services.Detect = func(context.Context, []plan.ToolKind) (plan.Tool, error) {
		return plan.Tool{Kind: plan.Terraform, Name: "Terraform", Version: "1.12.0"}, nil
	}
	services.Show = func(context.Context, plan.Tool, string) ([]byte, error) { return os.ReadFile("plan.json") }
	outputs := map[string]string{}
	for name, flags := range map[string][]string{"summary": {"--format=text"}, "details": {"--format=text", "--details"}, "json": {"--format=json"}} {
		var out, diagnostics bytes.Buffer
		code := runRoot(context.Background(), rootWithServices(services), append([]string{"check", "--plan=plan.json"}, flags...), &out, &diagnostics)
		if code != exitSuccess || diagnostics.Len() != 0 {
			t.Fatalf("%s: exit %d, stderr %q", name, code, diagnostics.String())
		}
		outputs[name] = out.String()
	}
	if err := json.Unmarshal([]byte(outputs["json"]), &document); err != nil {
		t.Fatal(err)
	}
	return outputs["summary"], outputs["details"], document
}

var accountID = regexp.MustCompile(`\b[0-9]{12}\b`)

// assertShortResult checks the default output: short, naming no account or
// ARN, with the header and the result the JSON verdict implies.
func assertShortResult(t *testing.T, text string, document report.Document, result string) {
	t.Helper()
	if lines := strings.Count(text, "\n"); lines >= maxDefaultLines {
		t.Errorf("default output is %d lines, not under %d:\n%s", lines, maxDefaultLines, text)
	}
	if strings.Contains(text, "arn:") || accountID.MatchString(text) {
		t.Errorf("default output names an ARN or account ID:\n%s", text)
	}
	if !strings.HasPrefix(text, "tfpreflight · AWS provider "+document.Provider.Version+" · eu-west-1 · ") {
		t.Errorf("default output header:\n%s", text)
	}
	if !strings.Contains(text, "\n"+result) {
		t.Errorf("default output lacks %q:\n%s", result, text)
	}
	if document.Summary.Blocking == 0 && regexp.MustCompile(`(?m)^FAIL `).MatchString(text) {
		t.Errorf("default output shows FAIL with no blocking finding:\n%s", text)
	}
}

var findingsLine = regexp.MustCompile(`(?m)^Findings: (\d+) blocking, (\d+) warnings?, (\d+) informational$`)

func assertHonestResult(t *testing.T, text string, document report.Document, verdict string) {
	t.Helper()
	summary := document.Summary
	if summary.Blocking != 0 || regexp.MustCompile(`(?m)^FAIL `).MatchString(text) {
		t.Errorf("a plan nothing in AWS was checked against has a blocking finding:\n%s", text)
	}
	if !strings.HasPrefix(summary.Verdict, verdict) {
		t.Errorf("verdict %q does not start %q", summary.Verdict, verdict)
	}
	if !strings.Contains(text, "\nPreflight: "+summary.Verdict+"\n") || strings.Contains(text, "PASSED") {
		t.Errorf("text verdict differs from JSON %q:\n%s", summary.Verdict, text)
	}
	if !strings.Contains(text, "\nRegion: eu-west-1 (from ") {
		t.Errorf("the provider's region was not resolved:\n%s", text)
	}
	counts := findingsLine.FindStringSubmatch(text)
	if counts == nil || counts[1] != strconv.Itoa(summary.Blocking) || counts[2] != strconv.Itoa(summary.Warnings) || counts[3] != strconv.Itoa(summary.Informational) {
		t.Errorf("text counts %v differ from JSON %+v", counts, summary)
	}
	if lines := strings.Count(text, "\n"); lines > maxRealWorldLines {
		t.Errorf("text output is %d lines, more than %d:\n%s", lines, maxRealWorldLines, text)
	}
}
