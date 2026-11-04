package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
)

// updateGolden rewrites the recorded result of the security group case. The
// nightly packs build passes it, so a pack update carries the new record for
// review. The checks that nothing blocks do not depend on it.
var updateGolden = flag.Bool("update-golden", false, "rewrite the recorded result of the security group case")

const securityGroupGolden = "result.golden"

// A security group rule whose referenced_security_group_id names a group that
// does not exist fails at apply with InvalidGroup.NotFound. With provider
// 6.70.0 the packs know nothing about aws_vpc_security_group_ingress_rule: its
// create method is defined on the base type it embeds, so the pack builder did
// not find it (analysis "create handler declaration not found"). tfpreflight
// then has no permission, dependency, conflict or quota rule for it.
//
// The result must say so. It may not call this plan checked, and it may not
// stay quiet about it. The counts are recorded in result.golden, so a pack
// update that gains a rule for the resource shows the new result in its pull
// request. Whatever the packs hold, this plan may never block, and a result
// with nothing checked must be PARTIAL.
func TestSecurityGroupRuleWithAMissingPeerIsReportedHonestly(t *testing.T) {
	t.Chdir("testdata/realworld-cases/sg-ingress-literal-peer")
	isolateAWS(t, true)
	t.Setenv("AWS_ENDPOINT_URL_STS", fakeSTS(t))
	summary, details, document := runRealWorldCheck(t)

	if document.Provider.Version != "6.70.0" {
		t.Fatalf("provider version = %q, want 6.70.0 from the lock file", document.Provider.Version)
	}
	got := document.Summary
	if got.Blocking != 0 {
		t.Fatalf("summary = %+v: the plan must never block", got)
	}
	if got.Checked == 0 {
		if !strings.HasPrefix(got.Verdict, "PARTIAL") {
			t.Errorf("verdict = %q, want PARTIAL when nothing was checked", got.Verdict)
		}
		if !strings.Contains(summary, "! Nothing could be checked.") {
			t.Errorf("the default output does not say nothing could be checked:\n%s", summary)
		}
	}

	record := fmt.Sprintf("checked %d\nunsupported %d\nwarnings %d\nverdict %s\n", got.Checked, got.Unsupported, got.Warnings, got.Verdict)
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
