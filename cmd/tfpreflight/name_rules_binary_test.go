package main

import (
	"bytes"
	"encoding/json"
	"fmt"
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

// The two name rules (a log group name, and a security group name within its
// VPC) through the built program, with a fake AWS that answers both listings
// and records what it was asked.
//
// The packs must hold the rules. Until a pack rebuild has put them in the
// built-in packs, point TFPREFLIGHT_NAME_RULE_PACKS at a pack directory that
// has them; with neither the test skips, and says why. To run the same cases
// through an earlier release, set TFPREFLIGHT_OLD_BINARY to its binary.

const (
	nameRulePacksEnv = "TFPREFLIGHT_NAME_RULE_PACKS"
	oldBinaryEnv     = "TFPREFLIGHT_OLD_BINARY"
	sgVPC            = "vpc-0123456789abcdef0"
)

// fakeNameAWS answers DescribeLogGroups and DescribeSecurityGroups from fixed
// bodies, and keeps every request it gets.
type fakeNameAWS struct {
	mu       sync.Mutex
	logs     string // JSON body for DescribeLogGroups
	groups   string // XML body for DescribeSecurityGroups
	requests []string
	URL      string
}

func newFakeNameAWS(t *testing.T, logs, groups string) *fakeNameAWS {
	t.Helper()
	f := &fakeNameAWS{logs: logs, groups: groups}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.Header.Get("X-Amz-Target") == "Logs_20140328.DescribeLogGroups":
			f.requests = append(f.requests, "DescribeLogGroups "+string(data))
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			_, _ = io.WriteString(w, f.logs)
		case strings.Contains(string(data), "Action=DescribeSecurityGroups"):
			f.requests = append(f.requests, "DescribeSecurityGroups "+string(data))
			w.Header().Set("Content-Type", "text/xml")
			_, _ = io.WriteString(w, f.groups)
		default:
			http.Error(w, "unsupported", http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	f.URL = server.URL
	return f
}

func (f *fakeNameAWS) asked(operation string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, request := range f.requests {
		if strings.HasPrefix(request, operation+" ") {
			out = append(out, request)
		}
	}
	return out
}

func logGroupsBody(names ...string) string {
	items := make([]string, len(names))
	for i, name := range names {
		items[i] = fmt.Sprintf(`{"logGroupName":%q}`, name)
	}
	return `{"logGroups":[` + strings.Join(items, ",") + `]}`
}

func securityGroupsBody(names ...string) string {
	var items strings.Builder
	for _, name := range names {
		fmt.Fprintf(&items, `<item><groupName>%s</groupName><groupId>sg-0abc</groupId><vpcId>%s</vpcId></item>`, name, sgVPC)
	}
	return `<DescribeSecurityGroupsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><requestId>r</requestId><securityGroupInfo>` + items.String() + `</securityGroupInfo></DescribeSecurityGroupsResponse>`
}

// planFile is a Terraform plan with the given resources, each created.
type planResource struct {
	Type, Name string
	After      map[string]any
	Unknown    map[string]any
	// References maps an attribute to the addresses its expression names.
	References map[string][]string
}

func planFile(t *testing.T, resources ...planResource) []byte {
	t.Helper()
	var changes, configured []any
	for _, r := range resources {
		after := map[string]any{"region": "us-east-1"}
		for k, v := range r.After {
			after[k] = v
		}
		unknown := map[string]any{"id": true, "arn": true}
		for k, v := range r.Unknown {
			unknown[k] = v
		}
		address := r.Type + "." + r.Name
		changes = append(changes, map[string]any{
			"address": address, "mode": "managed", "type": r.Type, "name": r.Name,
			"provider_name": "registry.terraform.io/hashicorp/aws", "schema_version": 0,
			"change": map[string]any{"actions": []string{"create"}, "before": nil, "after": after, "after_unknown": unknown, "before_sensitive": false, "after_sensitive": map[string]any{}},
		})
		expressions := map[string]any{}
		for k, v := range r.After {
			expressions[k] = map[string]any{"constant_value": v}
		}
		for k, refs := range r.References {
			expressions[k] = map[string]any{"references": refs}
		}
		configured = append(configured, map[string]any{
			"address": address, "mode": "managed", "type": r.Type, "name": r.Name,
			"provider_config_key": "aws", "expressions": expressions,
		})
	}
	document := map[string]any{
		"format_version": "1.2", "terraform_version": "1.12.0",
		"planned_values":   map[string]any{"root_module": map[string]any{}},
		"resource_changes": changes,
		"configuration": map[string]any{
			"provider_config": map[string]any{"aws": map[string]any{"name": "aws", "full_name": "registry.terraform.io/hashicorp/aws", "expressions": map[string]any{"region": map[string]any{"constant_value": "us-east-1"}}}},
			"root_module":     map[string]any{"resources": configured},
		},
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// nameRulePacks says which packs the cases run with: "" for the built-in ones,
// or a directory. ok is false when no pack set available holds the rules.
func nameRulePacks(t *testing.T) (dir string, ok bool) {
	t.Helper()
	if embeddedPacksHaveNameRules(t) {
		return "", true
	}
	if dir := os.Getenv(nameRulePacksEnv); dir != "" {
		return dir, true
	}
	return "", false
}

func embeddedPacksHaveNameRules(t *testing.T) bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "packs", "aws", "conflict", "generated-aws.json"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Contains(string(data), `"duplicate-error-listed"`)
}

// runNameCheck runs a binary's check on a plan with the fake AWS and returns
// its output and exit code.
func runNameCheck(t *testing.T, binary, packDir string, plan []byte, aws *fakeNameAWS) (string, int) {
	t.Helper()
	tools, work := t.TempDir(), t.TempDir()
	for name, content := range map[string][]byte{"terraform": []byte(savedPlanTerraform), "plan.json": plan} {
		if err := os.WriteFile(filepath.Join(tools, name), content, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(work, "main.tf"), []byte("provider \"aws\" {\n  region = \"us-east-1\"\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"check", "--provider-version", "6.71.0", "--details"}
	if packDir != "" {
		args = append(args, "--pack-dir", packDir)
	}
	command := exec.Command(binary, args...)
	command.Dir = work
	command.Env = []string{
		"PATH=" + tools + ":/usr/bin:/bin", "HOME=" + t.TempDir(), "TERM=dumb", "AWS_REGION=us-east-1",
		"AWS_EC2_METADATA_DISABLED=true", "AWS_CONFIG_FILE=" + os.DevNull, "AWS_SHARED_CREDENTIALS_FILE=" + os.DevNull,
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"AWS_MAX_ATTEMPTS=1", "AWS_ENDPOINT_URL=http://127.0.0.1:1", "AWS_ENDPOINT_URL_STS=" + fakeSTS(t), "AWS_ENDPOINT_URL_IAM=" + fakeIAMAllowAll(t),
		"AWS_ENDPOINT_URL_CLOUDWATCH_LOGS=" + aws.URL, "AWS_ENDPOINT_URL_EC2=" + aws.URL,
	}
	var out bytes.Buffer
	command.Stdout, command.Stderr = &out, &out
	err := command.Run()
	code := 0
	if exit, isExit := err.(*exec.ExitError); isExit {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatalf("running %s: %v", binary, err)
	}
	return out.String(), code
}

// conflictsLine is the "Conflicts:" line of the coverage section.
func conflictsLine(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Conflicts:") {
			return strings.Join(strings.Fields(line), " ")
		}
	}
	return ""
}

// completed fails the test unless the output is a finished check, so a run that
// stopped early cannot pass for one that found nothing.
func completed(t *testing.T, out string) {
	t.Helper()
	if !strings.Contains(out, "Preflight: ") {
		t.Fatalf("the check did not finish:\n%s", out)
	}
}

func logGroupPlan(t *testing.T, name string) []byte {
	return planFile(t, planResource{Type: "aws_cloudwatch_log_group", Name: "app", After: map[string]any{"name": name}})
}

func groupPlan(t *testing.T, name string) []byte {
	return planFile(t, planResource{Type: "aws_security_group", Name: "web", After: map[string]any{"name": name, "vpc_id": sgVPC}})
}

func groupInNewVPCPlan(t *testing.T, name string) []byte {
	return planFile(t,
		planResource{Type: "aws_vpc", Name: "main", After: map[string]any{"cidr_block": "10.0.0.0/16"}},
		planResource{
			Type: "aws_security_group", Name: "web", After: map[string]any{"name": name},
			Unknown: map[string]any{"vpc_id": true}, References: map[string][]string{"vpc_id": {"aws_vpc.main.id", "aws_vpc.main"}},
		})
}

func groupInDefaultVPCPlan(t *testing.T, name string) []byte {
	return planFile(t, planResource{Type: "aws_security_group", Name: "web", After: map[string]any{"name": name}, Unknown: map[string]any{"vpc_id": true}})
}

func TestBuiltBinaryChecksTheTwoNameRules(t *testing.T) {
	packDir, ok := nameRulePacks(t)
	if !ok {
		t.Skipf("the built-in packs have no listing name rules yet; set %s to a pack directory that does", nameRulePacksEnv)
	}
	binary := filepath.Join(buildBinary(t), "tfpreflight")

	t.Run("a log group name that is taken", func(t *testing.T) {
		aws := newFakeNameAWS(t, logGroupsBody("app", "app-prod"), "")
		out, _ := runNameCheck(t, binary, packDir, logGroupPlan(t, "app"), aws)
		completed(t, out)
		if !strings.Contains(out, "already exists") || strings.Contains(out, "No findings to show") {
			t.Errorf("a taken log group name was not reported:\n%s", out)
		}
		if got := aws.asked("DescribeLogGroups"); len(got) != 1 || !strings.Contains(got[0], `"logGroupNamePrefix":"app"`) {
			t.Errorf("lookups = %v", got)
		}
		if line := conflictsLine(out); !strings.Contains(line, "1 checked") {
			t.Errorf("conflicts coverage = %q, want 1 checked", line)
		}
	})
	t.Run("only a longer name shares the prefix", func(t *testing.T) {
		aws := newFakeNameAWS(t, logGroupsBody("app-prod", "app2"), "")
		out, _ := runNameCheck(t, binary, packDir, logGroupPlan(t, "app"), aws)
		completed(t, out)
		if strings.Contains(out, "already exists") || !strings.Contains(out, "No findings to show") {
			t.Errorf("app was reported taken because app-prod exists:\n%s", out)
		}
		if line := conflictsLine(out); !strings.Contains(line, "1 checked") {
			t.Errorf("conflicts coverage = %q, want 1 checked", line)
		}
	})
	t.Run("a log group name that is free", func(t *testing.T) {
		aws := newFakeNameAWS(t, logGroupsBody(), "")
		out, _ := runNameCheck(t, binary, packDir, logGroupPlan(t, "app"), aws)
		completed(t, out)
		if strings.Contains(out, "already exists") || !strings.Contains(out, "No findings to show") {
			t.Errorf("a free log group name was not clean:\n%s", out)
		}
	})
	t.Run("a security group name taken in its VPC", func(t *testing.T) {
		aws := newFakeNameAWS(t, "", securityGroupsBody("web"))
		out, _ := runNameCheck(t, binary, packDir, groupPlan(t, "web"), aws)
		completed(t, out)
		if !strings.Contains(out, "already exists") || strings.Contains(out, "No findings to show") {
			t.Errorf("a taken security group name was not reported:\n%s", out)
		}
		got := aws.asked("DescribeSecurityGroups")
		if len(got) != 1 || !strings.Contains(got[0], "Filter.1.Name=group-name") || !strings.Contains(got[0], "Filter.2.Value.1="+sgVPC) {
			t.Errorf("lookups = %v: both the name and the VPC must be sent", got)
		}
	})
	t.Run("a security group name that is free in its VPC", func(t *testing.T) {
		aws := newFakeNameAWS(t, "", securityGroupsBody())
		out, _ := runNameCheck(t, binary, packDir, groupPlan(t, "web"), aws)
		completed(t, out)
		if strings.Contains(out, "already exists") || !strings.Contains(out, "No findings to show") {
			t.Errorf("a free security group name was not clean:\n%s", out)
		}
	})
	t.Run("a security group in a VPC this plan creates is not looked up and not unchecked", func(t *testing.T) {
		aws := newFakeNameAWS(t, "", securityGroupsBody("web"))
		out, _ := runNameCheck(t, binary, packDir, groupInNewVPCPlan(t, "web"), aws)
		completed(t, out)
		if got := aws.asked("DescribeSecurityGroups"); len(got) != 0 {
			t.Errorf("a new VPC was looked up: %v", got)
		}
		if strings.Contains(out, "already exists") {
			t.Errorf("a new VPC was reported as a conflict:\n%s", out)
		}
		// Other checks may be partial here (permissions, the VPC's quota); the
		// name check must not be.
		if line := conflictsLine(out); line != "Conflicts: not applicable" {
			t.Errorf("conflicts coverage = %q, want not applicable", line)
		}
	})
	t.Run("a security group with no VPC given is not looked up and says it was not checked", func(t *testing.T) {
		aws := newFakeNameAWS(t, "", securityGroupsBody("web"))
		out, _ := runNameCheck(t, binary, packDir, groupInDefaultVPCPlan(t, "web"), aws)
		completed(t, out)
		if got := aws.asked("DescribeSecurityGroups"); len(got) != 0 {
			t.Errorf("a group with no known VPC was looked up: %v", got)
		}
		if strings.Contains(out, "already exists") {
			t.Errorf("reported a conflict it did not check:\n%s", out)
		}
	})
}

// copyPacksAsSchema copies a pack directory and rewrites its manifest's schema
// number. It stands for an earlier release reading packs that carry the new
// rules, which the schema number is there to prevent.
func copyPacksAsSchema(t *testing.T, from string, schema int) string {
	t.Helper()
	to := t.TempDir()
	err := filepath.WalkDir(filepath.Join(from, "aws"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(from, path)
		target := filepath.Join(to, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if relative == filepath.Join("aws", "manifest.json") {
			var manifest map[string]any
			if err := json.Unmarshal(data, &manifest); err != nil {
				return err
			}
			manifest["schema_version"] = schema
			if data, err = json.Marshal(manifest); err != nil {
				return err
			}
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return to
}

// An earlier release must behave exactly as before when the packs gain the name
// rules. Two lines stop it. The schema number: it refuses a pack set newer than
// it reads. And, if it were given the rules anyway as an old schema, the create
// semantics: it does not know them, so it sends no lookup and reports no finding.
func TestAnEarlierReleaseNeverRunsTheNameRules(t *testing.T) {
	old := os.Getenv(oldBinaryEnv)
	if old == "" {
		t.Skipf("set %s to an earlier release's binary to run this", oldBinaryEnv)
	}
	packDir, ok := nameRulePacks(t)
	if !ok {
		t.Skipf("no pack set with the name rules: set %s", nameRulePacksEnv)
	}
	if packDir == "" {
		packDir = filepath.Join("..", "..", "packs")
	}

	t.Run("it refuses packs of a newer schema", func(t *testing.T) {
		aws := newFakeNameAWS(t, logGroupsBody("app"), securityGroupsBody("web"))
		out, code := runNameCheck(t, old, packDir, logGroupPlan(t, "app"), aws)
		if code == 0 || !strings.Contains(out, "schema version") {
			t.Errorf("exit %d; the earlier release should refuse packs it cannot read:\n%s", code, out)
		}
		if len(aws.asked("DescribeLogGroups"))+len(aws.asked("DescribeSecurityGroups")) != 0 {
			t.Error("it sent a lookup")
		}
	})

	asOldSchema := copyPacksAsSchema(t, packDir, 2)
	for name, c := range map[string]struct {
		plan    []byte
		logs    string
		groups  string
		lookups string
	}{
		"a log group name that is taken":      {logGroupPlan(t, "app"), logGroupsBody("app"), "", "DescribeLogGroups"},
		"a log group with only a longer name": {logGroupPlan(t, "app"), logGroupsBody("app-prod"), "", "DescribeLogGroups"},
		"a security group name that is taken": {groupPlan(t, "web"), "", securityGroupsBody("web"), "DescribeSecurityGroups"},
		"a security group in a new VPC":       {groupInNewVPCPlan(t, "web"), "", securityGroupsBody("web"), "DescribeSecurityGroups"},
	} {
		t.Run("given the rules as an old schema: "+name, func(t *testing.T) {
			aws := newFakeNameAWS(t, c.logs, c.groups)
			out, code := runNameCheck(t, old, asOldSchema, c.plan, aws)
			if code != 0 {
				t.Fatalf("exit %d:\n%s", code, out)
			}
			completed(t, out)
			if got := aws.asked(c.lookups); len(got) != 0 {
				t.Errorf("the earlier release ran the new lookup: %v", got)
			}
			if strings.Contains(out, "already exists") {
				t.Errorf("the earlier release reported a conflict from the new rules:\n%s", out)
			}
			if strings.Contains(out, "panic") || strings.Contains(out, "goroutine") {
				t.Errorf("the earlier release crashed:\n%s", out)
			}
			t.Logf("conflicts coverage: %s", conflictsLine(out))
		})
	}
}
