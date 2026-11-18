package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tfpreflight/tfpreflight/rules"
)

// labelledInstanceAMIPacks is a copy of the repository's packs in which the
// aws_instance ami rule needs the capability given. It stands in for a pack
// that was built with the label, whatever the repository's packs carry.
func labelledInstanceAMIPacks(t *testing.T, label string) string {
	t.Helper()
	packs, err := filepath.Abs(filepath.Join("..", "..", "packs"))
	if err != nil {
		t.Fatal(err)
	}
	to := copyPacksWithRules(t, packs)
	file := filepath.Join(to, "aws", "dependency", "rules.json")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	pack, err := rules.ReadRangePack(data)
	if err != nil {
		t.Fatal(err)
	}
	if labelAMIRules(t, pack, label) == 0 {
		t.Fatal("the packs hold no aws_instance ami rule to label")
	}
	if data, err = pack.Encode(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data, 0o644); err != nil {
		t.Fatal(err)
	}
	setManifestDigest(t, to, "aws/dependency/rules.json", data)
	return to
}

// labelAMIRules adds the label to every aws_instance ami existence rule of the
// pack and returns how many it changed.
func labelAMIRules(t *testing.T, pack *rules.RangePack, label string) int {
	t.Helper()
	labelled := 0
	for i, field := range pack.Fields {
		if field.Name != "existence_rules" {
			continue
		}
		for j, entry := range field.Entries {
			var rule map[string]any
			if err := json.Unmarshal(entry.Value, &rule); err != nil {
				t.Fatal(err)
			}
			if rule["resource"] != "aws_instance" || rule["attribute"] != "ami" {
				continue
			}
			rule["requires"] = label
			value, err := json.Marshal(rule)
			if err != nil {
				t.Fatal(err)
			}
			pack.Fields[i].Entries[j].Value = value
			labelled++
		}
	}
	return labelled
}

// setManifestDigest records the digest of data as the manifest's digest of the
// pack file, so the changed copy opens as any pack set does.
func setManifestDigest(t *testing.T, packDir, name string, data []byte) {
	t.Helper()
	manifestFile := filepath.Join(packDir, "aws", "manifest.json")
	manifestData, err := os.ReadFile(manifestFile)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["files"].(map[string]any)[name] = rules.Digest(data)
	if manifestData, err = json.Marshal(manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestFile, manifestData, 0o644); err != nil {
		t.Fatal(err)
	}
}

// checkInstanceAMI runs the built program on a plan with one instance whose ami
// is the value given, against packs, and returns what it printed and the
// DescribeImages calls the fake EC2 received. The fake answers every call as
// "image not found".
func checkInstanceAMI(t *testing.T, packs, ami string) (string, []string) {
	t.Helper()
	var mu sync.Mutex
	var images []string
	ec2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "Action=DescribeImages") {
			mu.Lock()
			images = append(images, string(body))
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `<Response><Errors><Error><Code>InvalidAMIID.NotFound</Code><Message>The image id does not exist</Message></Error></Errors><RequestID>r</RequestID></Response>`)
	}))
	t.Cleanup(ec2.Close)
	plan := planFile(t, planResource{Type: "aws_instance", Name: "web", After: map[string]any{"ami": ami, "instance_type": "t3.micro"}})
	out, code := runNameCheck(t, filepath.Join(buildBinary(t), "tfpreflight"), packs, plan, &fakeNameAWS{URL: ec2.URL})
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	mu.Lock()
	defer mu.Unlock()
	return out, images
}

// A binary that does not know the capability behaves as beta.7 does with a
// pack built for a later version: the rule is not there, nothing is looked up,
// and the output says one newer check was left out.
func TestBuiltBinarySkipsTheAMIRuleWithoutTheCapability(t *testing.T) {
	out, images := checkInstanceAMI(t, labelledInstanceAMIPacks(t, "a-capability-from-the-future"), "ami-0c230065b91270bc6")
	if len(images) != 0 {
		t.Errorf("the rule ran without its capability: %v", images)
	}
	if want := "1 newer check needs a newer tfpreflight"; !strings.Contains(out, want) {
		t.Errorf("output lacks %q:\n%s", want, out)
	}
	if strings.Contains(out, "can't find") {
		t.Errorf("a missing-image warning came from a skipped rule:\n%s", out)
	}
}

// With the capability, the rule runs for an ordinary image id, and leaves a
// resolve: value alone, which AWS resolves itself.
func TestBuiltBinaryRunsTheAMIRuleWithTheCapability(t *testing.T) {
	packs := labelledInstanceAMIPacks(t, rules.CapabilityResolveValues)

	out, images := checkInstanceAMI(t, packs, "ami-0c230065b91270bc6")
	if len(images) != 1 {
		t.Errorf("an image id was looked up %d times, want once:\n%s", len(images), out)
	}
	if strings.Contains(out, "newer check") {
		t.Errorf("the rule was counted as left out:\n%s", out)
	}

	out, images = checkInstanceAMI(t, packs, "resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64")
	if len(images) != 0 {
		t.Errorf("a resolve: value was looked up: %v", images)
	}
	if strings.Contains(out, "can't find") || strings.Contains(out, "newer check") {
		t.Errorf("a resolve: value was reported:\n%s", out)
	}
}
