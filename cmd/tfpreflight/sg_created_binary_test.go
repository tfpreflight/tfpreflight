//go:build unix

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A Terraform that plans and shows a saved plan, so the built program runs the
// whole check on it.
const savedPlanTerraform = `#!/bin/sh
case $1 in
version) echo "Terraform v1.12.0" ;;
plan) for arg in "$@"; do case $arg in -out=*) echo plan > "${arg#-out=}" ;; esac; done ;;
show) cat "$(dirname "$0")/plan.json" ;;
*) exit 1 ;;
esac
`

// The same case as TestPlanThatCreatesAGroupStillWarnsAboutAMissingLiteralGroup,
// through the built program: its own rules, its own Terraform detection and its
// own AWS clients, which talk to a fake EC2 and STS.
func TestBuiltBinaryWarnsAboutAMissingGroupInAPlanThatCreatesOne(t *testing.T) {
	bin := buildBinary(t)
	copyFixtureWithPeer(t, "testdata/realworld-cases/sg-ingress-literal-peer", absentPeer)
	if !packsKnowThePeerRule(t) {
		t.Skip("the packs have no rule for the referenced security group yet")
	}
	plan, err := os.ReadFile("plan.json")
	if err != nil {
		t.Fatal(err)
	}
	work, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tools := t.TempDir()
	for name, content := range map[string][]byte{"terraform": []byte(savedPlanTerraform), "plan.json": planCreatingAGroup(t, plan)} {
		if err := os.WriteFile(filepath.Join(tools, name), content, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	ec2URL, asked := fakeEC2(t, absentPeer)
	command := exec.Command(filepath.Join(bin, "tfpreflight"), "check")
	command.Dir = work
	command.Env = []string{
		"PATH=" + tools + ":/usr/bin:/bin", "HOME=" + t.TempDir(), "TERM=dumb",
		"AWS_EC2_METADATA_DISABLED=true", "AWS_CONFIG_FILE=" + os.DevNull, "AWS_SHARED_CREDENTIALS_FILE=" + os.DevNull,
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"AWS_MAX_ATTEMPTS=1", "AWS_ENDPOINT_URL=http://127.0.0.1:1", "AWS_ENDPOINT_URL_STS=" + fakeSTS(t), "AWS_ENDPOINT_URL_EC2=" + ec2URL,
	}
	var out, diagnostics bytes.Buffer
	command.Stdout, command.Stderr = &out, &diagnostics
	if err := command.Run(); err != nil {
		t.Fatalf("exit: %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), diagnostics.String())
	}
	for _, want := range []string{
		"WARN  aws_vpc_security_group_ingress_rule.database_from_shared_services",
		"AWS can't find security group " + absentPeer,
		"! 1 warning to check, and apply will probably fail.",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	assertPeerLookup(t, asked(), absentPeer)
}
