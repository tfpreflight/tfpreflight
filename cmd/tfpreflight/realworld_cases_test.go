package main

import (
	"strings"
	"testing"
)

// A security group rule whose referenced_security_group_id names a group that
// does not exist fails at apply with InvalidGroup.NotFound. With provider
// 6.70.0 the packs know nothing about aws_vpc_security_group_ingress_rule: its
// create method is defined on the base type it embeds, so the pack builder did
// not find it (analysis "create handler declaration not found"). tfpreflight
// then has no permission, dependency, conflict or quota rule for it.
//
// The result must say so. It may not call this plan checked, and it may not
// stay quiet about it. This test pins what is reported today. When the packs
// gain a rule for the resource it fails on purpose: change it to expect the
// warning for referenced_security_group_id, and keep the plan.
func TestKnownGapSecurityGroupRuleWithAMissingPeerIsReportedUnsupported(t *testing.T) {
	t.Chdir("testdata/realworld-cases/sg-ingress-literal-peer")
	isolateAWS(t, true)
	t.Setenv("AWS_ENDPOINT_URL_STS", fakeSTS(t))
	summary, details, document := runRealWorldCheck(t)

	if document.Provider.Version != "6.70.0" {
		t.Fatalf("provider version = %q, want 6.70.0 from the lock file", document.Provider.Version)
	}
	got := document.Summary
	if got.Checked != 0 || got.Unsupported != 1 || got.Blocking != 0 || got.Warnings != 0 {
		t.Fatalf("summary = %+v, want the one resource unsupported and nothing checked, blocking or warned about", got)
	}
	if !strings.HasPrefix(got.Verdict, "PARTIAL - nothing was verified") {
		t.Errorf("verdict = %q, want PARTIAL - nothing was verified", got.Verdict)
	}
	if !strings.Contains(summary, "! Nothing could be checked.") {
		t.Errorf("the default output does not say nothing could be checked:\n%s", summary)
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
