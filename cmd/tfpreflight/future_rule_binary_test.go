package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/rules"
)

// copyPacksWithRules copies a pack directory and adds the given conflict rules
// to its conflict range pack, for every version it covers, then fixes the
// manifest's digest of that file. The rules are written as a pack builder
// would, so the copy opens as any pack set does.
func copyPacksWithRules(t *testing.T, from string, added ...map[string]any) string {
	t.Helper()
	to := t.TempDir()
	err := filepath.WalkDir(filepath.Join(from, "aws"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(from, path)
		if entry.IsDir() {
			return os.MkdirAll(filepath.Join(to, relative), 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(to, relative), data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(to, "aws", "conflict", "generated-aws.json")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	pack, err := rules.ReadRangePack(data)
	if err != nil {
		t.Fatal(err)
	}
	span := []rules.VersionRange{{pack.Versions[0], pack.Versions[len(pack.Versions)-1]}}
	for i, field := range pack.Fields {
		if field.Name != "rules" {
			continue
		}
		for _, rule := range added {
			value, _ := json.Marshal(rule)
			pack.Fields[i].Entries = append(pack.Fields[i].Entries, rules.RangeEntry{Versions: span, Value: value})
		}
	}
	if data, err = pack.Encode(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data, 0o644); err != nil {
		t.Fatal(err)
	}
	manifestFile := filepath.Join(to, "aws", "manifest.json")
	manifestData, err := os.ReadFile(manifestFile)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["files"].(map[string]any)["aws/conflict/generated-aws.json"] = rules.Digest(data)
	if manifestData, err = json.Marshal(manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestFile, manifestData, 0o644); err != nil {
		t.Fatal(err)
	}
	return to
}

// futureRule is a conflict rule for a resource type, written as the pack
// builder writes one, needing the capability given (none when empty).
func futureRule(resourceType, service, operation, requires string) map[string]any {
	rule := map[string]any{
		"provider_version": rules.VersionToken, "resource_type": resourceType, "identity_field": "name",
		"lookup_service": service, "lookup_operation": operation, "create_semantics": "duplicate-error",
		"scope": "account_region", "trust": "generated", "semantics_evidence": map[string]any{"source": "test"},
	}
	if requires != "" {
		rule["requires"] = requires
	}
	return rule
}

// verdictLines are the lines of an output that state the result.
func verdictLines(out string) string {
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		for _, prefix := range []string{"Preflight:", "Findings:", "Resources:"} {
			if strings.HasPrefix(trimmed, prefix) {
				lines = append(lines, trimmed)
			}
		}
	}
	return strings.Join(lines, "\n")
}

const futureCapability = "a-capability-from-the-future"

// futureFixture is the built binary, the repository's packs, a plan with a log
// group and a security group, and what the check says with the packs as they are.
type futureFixture struct {
	binary, packs string
	plan          []byte
	baseline      string
}

func newFutureFixture(t *testing.T) futureFixture {
	t.Helper()
	packs, err := filepath.Abs(filepath.Join("..", "..", "packs"))
	if err != nil {
		t.Fatal(err)
	}
	f := futureFixture{
		binary: filepath.Join(buildBinary(t), "tfpreflight"), packs: packs,
		plan: planFile(t,
			planResource{Type: "aws_cloudwatch_log_group", Name: "app", After: map[string]any{"name": "app"}},
			planResource{Type: "aws_security_group", Name: "web", After: map[string]any{"name": "web", "vpc_id": sgVPC}}),
	}
	f.baseline, _ = f.run(t, packs)
	if strings.Contains(f.baseline, "newer check") {
		t.Fatalf("the unmodified packs already mention newer checks:\n%s", f.baseline)
	}
	return f
}

// run checks the plan against a pack directory, with a fake AWS that would
// answer both name lookups as "taken".
func (f futureFixture) run(t *testing.T, packDir string) (string, *fakeNameAWS) {
	t.Helper()
	aws := newFakeNameAWS(t, logGroupsBody("app"), securityGroupsBody("web"))
	out, code := runNameCheck(t, f.binary, packDir, f.plan, aws)
	completed(t, out)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	return out, aws
}

func logGroupRule(requires string) map[string]any {
	return futureRule("aws_cloudwatch_log_group", "cloudwatchlogs", "DescribeLogGroups", requires)
}

func groupRule(requires string) map[string]any {
	return futureRule("aws_security_group", "ec2", "DescribeSecurityGroups", requires)
}

// skippedCleanly checks that rules needing a capability this version lacks left
// no trace but the note: no lookup, the same result and coverage as without
// them, and the note with the count.
func (f futureFixture) skippedCleanly(t *testing.T, out string, aws *fakeNameAWS, note string) {
	t.Helper()
	if len(aws.requests) != 0 {
		t.Errorf("a lookup was sent: %v", aws.requests)
	}
	if got, want := verdictLines(out), verdictLines(f.baseline); got != want {
		t.Errorf("the result changed.\nwith the rules:\n%s\nwithout them:\n%s", got, want)
	}
	if got, want := conflictsLine(out), conflictsLine(f.baseline); got != want {
		t.Errorf("conflicts coverage %q, without the rules %q", got, want)
	}
	if !strings.Contains(out, note) {
		t.Errorf("no note %q:\n%s", note, out)
	}
}

// A pack may gain a kind of check that this version cannot run. Packs carry it
// with a capability label, and this version, which does not know the label,
// must leave the rule out as if it were not there: no lookup, nothing marked
// unsupported, the same result, and one line saying how many it left out.
func TestBuiltBinarySkipsARuleFromTheFutureCleanly(t *testing.T) {
	f := newFutureFixture(t)
	out, aws := f.run(t, copyPacksWithRules(t, f.packs, logGroupRule(futureCapability)))
	f.skippedCleanly(t, out, aws, "tfpreflight: note: 1 newer check needs a newer tfpreflight; update tfpreflight to run it")
}

func TestBuiltBinaryCountsTheRulesFromTheFuture(t *testing.T) {
	f := newFutureFixture(t)
	out, aws := f.run(t, copyPacksWithRules(t, f.packs, logGroupRule(futureCapability), groupRule(futureCapability)))
	f.skippedCleanly(t, out, aws, "tfpreflight: note: 2 newer checks need a newer tfpreflight; update tfpreflight to run them")
}

// The control: the same rule with no label is an ordinary rule this version
// cannot answer (its lookup has no spec in these packs), which it reports as
// unsupported. The label is what makes the difference.
func TestTheSameRuleWithoutALabelIsUnsupportedNotSkipped(t *testing.T) {
	f := newFutureFixture(t)
	out, _ := f.run(t, copyPacksWithRules(t, f.packs, logGroupRule("")))
	if line := conflictsLine(out); !strings.Contains(line, "1 unsupported") {
		t.Errorf("conflicts coverage = %q, want 1 unsupported", line)
	}
	if strings.Contains(out, "newer check") {
		t.Errorf("a rule with no label was counted as a newer check:\n%s", out)
	}
}

// A capability this version knows is not skipped.
func TestARuleNeedingAKnownCapabilityIsKept(t *testing.T) {
	f := newFutureFixture(t)
	out, _ := f.run(t, copyPacksWithRules(t, f.packs, logGroupRule(rules.CapabilityListingLookups)))
	if line := conflictsLine(out); !strings.Contains(line, "1 unsupported") || strings.Contains(out, "newer check") {
		t.Errorf("conflicts coverage = %q:\n%s", line, out)
	}
}
