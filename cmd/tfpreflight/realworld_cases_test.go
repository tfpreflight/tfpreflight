package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/checks/dependencies/adapters"
	"github.com/tfpreflight/tfpreflight/internal/report"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// updateGolden rewrites the recorded result of the security group case. The
// nightly packs build passes it, so a pack update carries the new record for
// review. The checks below do not depend on it.
var updateGolden = flag.Bool("update-golden", false, "rewrite the recorded result of the security group case")

const securityGroupGolden = "result.golden"

const (
	missingPeer = "sg-0123456789abcdef0" // referenced_security_group_id in plan.json
	ownGroup    = "sg-0fedcba9876543210" // security_group_id in plan.json
)

// fakeEC2 answers DescribeSecurityGroups: the groups named in missing do not
// exist, any other group does. It records every group it is asked about, and
// refuses any other call.
func fakeEC2(t *testing.T, missing ...string) (url string, asked func() []string) {
	t.Helper()
	var mu sync.Mutex
	var groups []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.PostForm.Get("Action") != "DescribeSecurityGroups" {
			http.Error(w, "unsupported", http.StatusBadRequest)
			return
		}
		id := r.PostForm.Get("GroupId.1")
		mu.Lock()
		groups = append(groups, id)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/xml")
		for _, gone := range missing {
			if id == gone {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `<Response><Errors><Error><Code>InvalidGroup.NotFound</Code><Message>The security group '`+id+`' does not exist</Message></Error></Errors><RequestID>1</RequestID></Response>`)
				return
			}
		}
		_, _ = io.WriteString(w, `<DescribeSecurityGroupsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><requestId>1</requestId><securityGroupInfo><item><groupId>`+id+`</groupId></item></securityGroupInfo></DescribeSecurityGroupsResponse>`)
	}))
	t.Cleanup(server.Close)
	return server.URL, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), groups...)
	}
}

// packsKnowThePeerRule says whether the shipped dependency pack for provider
// 6.70.0 has a rule for the security group a rule refers to.
func packsKnowThePeerRule(t *testing.T) bool {
	t.Helper()
	rules, err := adapters.Rules("6.70.0")
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		if rule.Resource == "aws_vpc_security_group_ingress_rule" && rule.Attribute == "referenced_security_group_id" {
			return true
		}
	}
	return false
}

// A security group rule whose referenced_security_group_id names a group that
// does not exist fails at apply with InvalidGroup.NotFound.
//
// Until the packs carried a rule for aws_vpc_security_group_ingress_rule
// (the pack builder missed its create method, which is defined on a type it
// embeds), tfpreflight had nothing to check it with, and it had to say so. Once
// the packs carry the rule, AWS answers that the group does not exist, and the
// result must be a warning on referenced_security_group_id: never a block, as
// a rule from the pack builder is only generated knowledge.
//
// The test follows what the packs hold, so it passes before and after a pack
// update, and the packs pull request shows the change in result.golden.
func TestSecurityGroupRuleWithAMissingPeerIsReportedHonestly(t *testing.T) {
	t.Chdir("testdata/realworld-cases/sg-ingress-literal-peer")
	isolateAWS(t, true)
	t.Setenv("AWS_ENDPOINT_URL_STS", fakeSTS(t))
	ec2URL, asked := fakeEC2(t, missingPeer)
	t.Setenv("AWS_ENDPOINT_URL_EC2", ec2URL)
	summary, details, document := runRealWorldCheck(t)

	if document.Provider.Version != "6.70.0" {
		t.Fatalf("provider version = %q, want 6.70.0 from the lock file", document.Provider.Version)
	}
	got := document.Summary
	// Whatever the packs hold, this plan never blocks, and a run that checked
	// nothing never reads as a pass.
	if got.Blocking != 0 {
		t.Fatalf("summary = %+v: the plan must never block", got)
	}
	for _, finding := range document.Findings {
		if finding.Blocking {
			t.Errorf("finding %s blocks: %+v", finding.ID, finding)
		}
	}
	assertNothingCheckedNeverPasses(t, summary, document)

	if packsKnowThePeerRule(t) {
		assertPeerWarning(t, summary, document, asked())
	} else {
		assertNoRuleYet(t, details, got)
	}
	checkGolden(t, details, document)
}

// assertNoRuleYet is the result while the packs have no rule for the resource:
// it is unsupported, and nothing was checked or warned about.
func assertNoRuleYet(t *testing.T, details string, got report.Summary) {
	t.Helper()
	if got.Checked != 0 || got.Unsupported != 1 || got.Warnings != 0 {
		t.Errorf("summary = %+v, want the one resource unsupported and nothing checked or warned about", got)
	}
	for _, line := range []string{
		"Resources: 0 checked, 0 partial, 0 not covered, 1 unsupported",
		"Dependencies:                    0 checked, 0 partial, 1 no additional rule discovered, 0 unsupported",
	} {
		if !strings.Contains(details, line) {
			t.Errorf("--details lacks %q:\n%s", line, details)
		}
	}
}

// checkGolden compares the result with result.golden, or rewrites it.
func checkGolden(t *testing.T, details string, document report.Document) {
	t.Helper()
	got := document.Summary
	record := fmt.Sprintf("checked %d\nunsupported %d\nwarnings %d\nblocking %d\nverdict %s\n", got.Checked, got.Unsupported, got.Warnings, got.Blocking, got.Verdict)
	for _, finding := range document.Findings {
		record += fmt.Sprintf("finding %s %s blocking=%v\n", finding.ID, finding.Severity, finding.Blocking)
	}
	for _, line := range strings.Split(details, "\n") {
		if strings.HasPrefix(line, "Resources:") || strings.HasPrefix(line, "Dependencies:") {
			record += line + "\n"
		}
	}
	if *updateGolden {
		if err := os.WriteFile(securityGroupGolden, []byte(record), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(securityGroupGolden)
	if err != nil || string(want) != record {
		t.Fatalf("the result changed from %s (run go test ./cmd/tfpreflight -run TestSecurityGroupRuleWithAMissingPeer -update-golden):\n%s\nrecorded:\n%s\n%v", securityGroupGolden, record, string(want), err)
	}
}

// assertPeerWarning checks the result when the packs carry the rule and AWS
// says the referenced group does not exist: one warning, on the referenced
// group, that does not block.
func assertPeerWarning(t *testing.T, summary string, document report.Document, groups []string) {
	t.Helper()
	got := document.Summary
	if got.Blocking != 0 || got.Warnings != 1 {
		t.Errorf("summary = %+v, want exactly one warning and nothing blocking", got)
	}
	if got.Verdict != "PASSED WITH WARNINGS (PARTIAL)" {
		t.Errorf("verdict = %q, want PASSED WITH WARNINGS (PARTIAL)", got.Verdict)
	}
	var found []report.Finding
	for _, finding := range document.Findings {
		if finding.ID == "aws.dependency-missing" {
			found = append(found, finding)
		}
	}
	if len(found) != 1 {
		t.Fatalf("findings = %+v, want one aws.dependency-missing", document.Findings)
	}
	assertPeerFinding(t, found[0])
	assertPeerLookup(t, groups)
	assertPeerWording(t, summary)
}

func assertPeerFinding(t *testing.T, finding report.Finding) {
	t.Helper()
	if finding.Resource != "aws_vpc_security_group_ingress_rule.database_from_shared_services" {
		t.Errorf("warning is on %q", finding.Resource)
	}
	if finding.Severity != model.SeverityWarning || finding.Blocking {
		t.Errorf("finding = %+v, want a warning that does not block", finding)
	}
	if finding.Message != "Referenced resource does not exist" {
		t.Errorf("warning title = %q", finding.Message)
	}
	if !strings.Contains(finding.Reason, "referenced_security_group_id") || !strings.Contains(finding.Reason, missingPeer) {
		t.Errorf("warning does not name referenced_security_group_id and %s: %q", missingPeer, finding.Reason)
	}
	if strings.Contains(finding.Reason, ownGroup) {
		t.Errorf("warning names the rule's own group, which exists: %q", finding.Reason)
	}
}

// assertPeerLookup checks AWS was asked about the missing group.
func assertPeerLookup(t *testing.T, groups []string) {
	t.Helper()
	sort.Strings(groups)
	for _, id := range groups {
		if id == missingPeer {
			return
		}
	}
	t.Errorf("AWS was not asked about %s, only %v", missingPeer, groups)
}

// assertPeerWording checks the short output says what AWS answered and when it
// could still be wrong, and does not read as a clean plan.
func assertPeerWording(t *testing.T, summary string) {
	t.Helper()
	for _, want := range []string{
		"AWS can't find security group " + missingPeer + " in this account and region; unless it is in a peered VPC or another account, apply will fail.",
		"1 warning to check, and apply will probably fail. Not blocking: tfpreflight has not confirmed that AWS rejects this create.",
	} {
		if !strings.Contains(summary, want) {
			t.Errorf("the default output lacks %q:\n%s", want, summary)
		}
	}
}

// errorReporter is the part of *testing.T the guard uses, so a test can check
// that the guard reports what it should.
type errorReporter interface {
	Helper()
	Errorf(format string, args ...any)
}

// assertNothingCheckedNeverPasses is the rule for a run in which no check was
// answered: its verdict is PARTIAL (or FAILED), never a pass, and the default output says
// so in one of the two honest ways.
func assertNothingCheckedNeverPasses(t errorReporter, summary string, document report.Document) {
	t.Helper()
	got := document.Summary
	// Something was checked when AWS answered any one check, even if no
	// resource was checked in full.
	for _, resource := range document.Coverage {
		for _, status := range resource.Checks {
			if status == model.CheckChecked {
				return
			}
		}
	}
	for _, passed := range []string{"PASSED", "COMPLETE"} {
		if strings.HasPrefix(got.Verdict, passed) {
			t.Errorf("verdict %q: a run with nothing checked reads as a pass", got.Verdict)
		}
	}
	if !strings.HasPrefix(got.Verdict, "PARTIAL") && !strings.HasPrefix(got.Verdict, "FAILED") {
		t.Errorf("verdict %q is neither PARTIAL nor FAILED", got.Verdict)
	}
	if strings.Contains(summary, "✓") || strings.Contains(summary, "No problems found") {
		t.Errorf("a run with nothing checked says it found no problems:\n%s", summary)
	}
	if !strings.Contains(summary, "! Nothing could be checked.") && !strings.Contains(summary, "! AWS checks failed: ") {
		t.Errorf("the default output says neither \"Nothing could be checked\" nor \"AWS checks failed\":\n%s", summary)
	}
}

type recorder struct{ errors []string }

func (r *recorder) Helper() {}
func (r *recorder) Errorf(format string, args ...any) {
	r.errors = append(r.errors, fmt.Sprintf(format, args...))
}

func nothingAnswered() []report.ResourceCoverage {
	return []report.ResourceCoverage{{Resource: "r.x", Checks: map[string]model.CheckStatus{"dependencies": model.CheckNotApplicable, "permissions": model.CheckUnverifiable}}}
}

// The guard has to fail for a run that checked nothing and still reads as a
// pass, and for one that says nothing about it, or it protects nothing.
func TestNothingCheckedGuardCatchesAPassAndASilentRun(t *testing.T) {
	honest := "! Nothing could be checked.\n"
	for name, c := range map[string]struct {
		verdict, text string
		coverage      []report.ResourceCoverage
		wantErrors    bool
	}{
		"honest, nothing verified":     {"PARTIAL - nothing was verified", honest, nothingAnswered(), false},
		"honest, AWS checks failed":    {"PARTIAL - AWS checks failed: x", "! AWS checks failed: x.\n", nothingAnswered(), false},
		"passed with nothing checked":  {"PASSED (PARTIAL)", honest, nothingAnswered(), true},
		"complete with nothing":        {"COMPLETE", honest, nothingAnswered(), true},
		"says no problems found":       {"PARTIAL - nothing was verified", "✓ No problems found.\n", nothingAnswered(), true},
		"silent: neither honest line":  {"PARTIAL - nothing was verified", "tfpreflight\n", nothingAnswered(), true},
		"something checked is allowed": {"PASSED (PARTIAL)", "! 1 warning to check.\n", []report.ResourceCoverage{{Resource: "r.x", Checks: map[string]model.CheckStatus{"dependencies": model.CheckChecked}}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			var r recorder
			assertNothingCheckedNeverPasses(&r, c.text, report.Document{Coverage: c.coverage, Summary: report.Summary{Verdict: c.verdict}})
			if got := len(r.errors) > 0; got != c.wantErrors {
				t.Fatalf("errors = %v, want errors: %v", r.errors, c.wantErrors)
			}
		})
	}
}
