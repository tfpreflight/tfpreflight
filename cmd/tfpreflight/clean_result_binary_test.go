//go:build unix

package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeIAMAllowAll answers SimulatePrincipalPolicy as IAM does when the identity
// may do everything: one "allowed" result for each action and resource asked.
func fakeIAMAllowAll(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.PostForm.Get("Action") != "SimulatePrincipalPolicy" {
			http.Error(w, "unsupported", http.StatusBadRequest)
			return
		}
		resources := []string{"*"}
		if asked := formList(r, "ResourceArns.member."); len(asked) > 0 {
			resources = asked
		}
		var body strings.Builder
		body.WriteString(`<SimulatePrincipalPolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><SimulatePrincipalPolicyResult><EvaluationResults>`)
		for _, action := range formList(r, "ActionNames.member.") {
			for _, resource := range resources {
				fmt.Fprintf(&body, `<member><EvalActionName>%s</EvalActionName><EvalResourceName>%s</EvalResourceName><EvalDecision>allowed</EvalDecision><MatchedStatements/><MissingContextValues/></member>`, action, resource)
			}
		}
		body.WriteString(`</EvaluationResults><IsTruncated>false</IsTruncated></SimulatePrincipalPolicyResult><ResponseMetadata><RequestId>1</RequestId></ResponseMetadata></SimulatePrincipalPolicyResponse>`)
		w.Header().Set("Content-Type", "text/xml")
		_, _ = io.WriteString(w, body.String())
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// formList reads the numbered members of a query parameter list.
func formList(r *http.Request, prefix string) []string {
	var values []string
	for index := 1; ; index++ {
		value := r.PostForm.Get(fmt.Sprintf("%s%d", prefix, index))
		if value == "" {
			return values
		}
		values = append(values, value)
	}
}

// builtCheckOutput runs the built program's default check on a saved plan, as
// an identity that may do everything, with every AWS lookup unreachable. The
// answers a clean result depends on are then only the ones the packs say it
// can give without AWS.
func builtCheckOutput(t *testing.T, fixture string) string {
	t.Helper()
	bin := buildBinary(t)
	copyFixtureWithPeer(t, fixture, "unused")
	work, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := os.ReadFile("plan.json")
	if err != nil {
		t.Fatal(err)
	}
	tools := t.TempDir()
	for name, content := range map[string][]byte{"terraform": []byte(savedPlanTerraform), "plan.json": plan} {
		if err := os.WriteFile(filepath.Join(tools, name), content, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command(filepath.Join(bin, "tfpreflight"), "check")
	command.Dir = work
	command.Env = []string{
		"PATH=" + tools + ":/usr/bin:/bin", "HOME=" + t.TempDir(), "TERM=dumb",
		"AWS_EC2_METADATA_DISABLED=true", "AWS_CONFIG_FILE=" + os.DevNull, "AWS_SHARED_CREDENTIALS_FILE=" + os.DevNull,
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"AWS_MAX_ATTEMPTS=1", "AWS_ENDPOINT_URL=http://127.0.0.1:1", "AWS_ENDPOINT_URL_STS=" + fakeSTS(t), "AWS_ENDPOINT_URL_IAM=" + fakeIAMAllowAll(t),
	}
	var out, diagnostics bytes.Buffer
	command.Stdout, command.Stderr = &out, &diagnostics
	if err := command.Run(); err != nil {
		t.Fatalf("exit: %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), diagnostics.String())
	}
	return out.String()
}

// A resource the packs hold only permission rules for (a log stream has
// no name, reference or quota rule) used to be reported as "Checked 1 of 1
// resource fully". It must say it was only checked for permissions.
func TestBuiltBinaryDoesNotSayFullyCheckedWhenOnlyPermissionsWere(t *testing.T) {
	out := builtCheckOutput(t, "testdata/realworld-cases/log-stream-no-checks")
	for _, want := range []string{
		"✓ No problems found in the checks tfpreflight ran.",
		"1 of 1 resource was only checked for permissions; tfpreflight has no other checks for it yet. Details: tfpreflight check --details",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "fully") {
		t.Errorf("the output says \"fully\":\n%s", out)
	}
}

// The plan of an instance in a subnet that does not exist, with no AWS to ask.
// Packs before the aws_instance.subnet_id rule have only its permissions to
// check; packs with it start a subnet lookup that cannot finish here. Either
// way the result must not read as everything having been checked.
func TestBuiltBinaryDoesNotSayFullyCheckedForAnInstanceInAMissingSubnet(t *testing.T) {
	out := builtCheckOutput(t, "testdata/realworld-cases/instance-in-missing-subnet")
	if !strings.Contains(out, "✓ No problems found in the checks tfpreflight ran.") {
		t.Errorf("output lacks the clean result line:\n%s", out)
	}
	permissionsOnly := "1 of 1 resource was only checked for permissions; tfpreflight has no other checks for it yet."
	couldNotFinish := "1 of 1 resource had a check that could not finish."
	if !strings.Contains(out, permissionsOnly) && !strings.Contains(out, couldNotFinish) {
		t.Errorf("output says neither that the resource was only checked for permissions nor that a check could not finish:\n%s", out)
	}
	if strings.Contains(out, "fully") {
		t.Errorf("the output says \"fully\":\n%s", out)
	}
}
