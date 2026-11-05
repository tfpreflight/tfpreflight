package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// refusingEC2 answers every call with the given status and error code, as AWS
// does for a role that may not describe security groups.
func refusingEC2(t *testing.T, status int, code string) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `<Response><Errors><Error><Code>`+code+`</Code><Message>refused</Message></Error></Errors><RequestID>1</RequestID></Response>`)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// A dependency check that could not finish is never silent. When AWS will not
// answer the lookup for referenced_security_group_id, the resource is counted
// partial, and --details names it under Not checked with the attribute and the
// reason. It is information only: it never warns and never blocks.
func TestPartialDependencyCheckIsListedUnderNotChecked(t *testing.T) {
	t.Chdir("testdata/realworld-cases/sg-ingress-literal-peer")
	isolateAWS(t, true)
	t.Setenv("AWS_ENDPOINT_URL_STS", fakeSTS(t))
	t.Setenv("AWS_ENDPOINT_URL_EC2", refusingEC2(t, http.StatusForbidden, "UnauthorizedOperation"))
	summary, details, document := runRealWorldCheck(t)

	if got := document.Summary; got.Blocking != 0 || got.Warnings != 0 {
		t.Fatalf("summary = %+v: a lookup that got no answer must not warn or block", got)
	}
	assertNothingCheckedNeverPasses(t, summary, document)

	const resource = "aws_vpc_security_group_ingress_rule.database_from_shared_services"
	for _, want := range []string{
		"Not checked (gaps in coverage, not predicted failures):",
		resource + ": referenced_security_group_id: the target could not be inspected: AWS inspection error: UnauthorizedOperation",
		"The lookup got no usable answer",
		"Dependencies:                    0 checked, 1 partial",
	} {
		if !strings.Contains(details, want) {
			t.Errorf("--details lacks %q:\n%s", want, details)
		}
	}
	listed := false
	for _, finding := range document.Findings {
		if finding.ID == "aws.dependency-coverage-incomplete" && finding.Resource == resource && strings.Contains(finding.Reason, "referenced_security_group_id: the target could not be inspected") {
			listed = true
		}
	}
	if !listed {
		t.Errorf("the JSON report has no coverage note for %s: %+v", resource, document.Findings)
	}
}
