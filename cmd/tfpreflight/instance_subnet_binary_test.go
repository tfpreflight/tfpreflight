package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// An aws_instance whose subnet_id names a subnet AWS does not have is a warning
// in the built program, with the rules built into it. The fake AWS answers the
// subnet lookup the way EC2 does for a subnet that does not exist.
func TestBuiltBinaryWarnsAboutAnInstanceInAMissingSubnet(t *testing.T) {
	bin := buildBinary(t)
	copyFixtureWithPeer(t, "testdata/realworld-cases/instance-in-missing-subnet", "unused")
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
	var mu sync.Mutex
	var asked []string
	ec2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		asked = append(asked, string(body))
		mu.Unlock()
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `<Response><Errors><Error><Code>InvalidSubnetID.NotFound</Code><Message>The subnet ID does not exist</Message></Error></Errors><RequestID>r</RequestID></Response>`)
	}))
	t.Cleanup(ec2.Close)

	command := exec.Command(filepath.Join(bin, "tfpreflight"), "check", "--provider-version", "6.71.0")
	command.Dir = work
	command.Env = []string{
		"PATH=" + tools + ":/usr/bin:/bin", "HOME=" + t.TempDir(), "TERM=dumb",
		"AWS_EC2_METADATA_DISABLED=true", "AWS_CONFIG_FILE=" + os.DevNull, "AWS_SHARED_CREDENTIALS_FILE=" + os.DevNull,
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"AWS_MAX_ATTEMPTS=1", "AWS_ENDPOINT_URL=http://127.0.0.1:1", "AWS_ENDPOINT_URL_STS=" + fakeSTS(t), "AWS_ENDPOINT_URL_IAM=" + fakeIAMAllowAll(t),
		"AWS_ENDPOINT_URL_EC2=" + ec2.URL,
	}
	var out bytes.Buffer
	command.Stdout, command.Stderr = &out, &out
	if err := command.Run(); err != nil {
		t.Fatalf("exit: %v\n%s", err, out.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(asked) != 1 || !strings.Contains(asked[0], "Action=DescribeSubnets") {
		t.Errorf("AWS was asked %v, want one DescribeSubnets", asked)
	}
	if want := "AWS can't find subnet subnet-0a1b2c3d4e5f60718 in this account and region"; !strings.Contains(out.String(), want) {
		t.Errorf("output lacks %q:\n%s", want, out.String())
	}
}
