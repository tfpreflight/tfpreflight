package packs

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/tfpreflight/tfpreflight/rules"
)

// A pack set with one conflict range pack and one lookup range pack, each with
// an entry that needs a capability from the future.
func setWithFutureEntries(t *testing.T) *Set {
	t.Helper()
	span := []rules.VersionRange{{"1.0.0", "1.0.0"}}
	pack := func(name, field string, entries ...string) []byte {
		var values []rules.RangeEntry
		for _, entry := range entries {
			values = append(values, rules.RangeEntry{Versions: span, Value: json.RawMessage(entry)})
		}
		data, err := (&rules.RangePack{
			Format: rules.RangePackFormat, Name: name, Versions: []string{"1.0.0"},
			Fields: []rules.RangeField{{Name: field, Kind: rules.FieldList, Present: span, Entries: values}},
		}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	files := map[string][]byte{
		"aws/conflict/generated-aws.json": pack("aws/conflict/generated-aws-{provider_version}.json", "rules",
			`{"resource_type":"aws_a"}`, `{"resource_type":"aws_b","requires":"a-capability-from-the-future"}`, `{"resource_type":"aws_c","requires":"a-capability-from-the-future"}`),
		"aws/lookup/conflict-specs.json": pack("aws/lookup/conflict-specs-{provider_version}.json", "specs",
			`{"service":"x","operation":"Describe","protocol":"awsJson1_1","target":"X.Describe","method":"POST","path":"/"}`,
			`{"service":"x","operation":"DescribeNew","protocol":"a-protocol-from-the-future","requires":"a-capability-from-the-future"}`),
	}
	fsys := fstest.MapFS{}
	manifest := rules.Manifest{SchemaVersion: rules.SchemaVersion, Provider: "aws", Files: map[string]string{}, Versions: []string{"1.0.0"}}
	for name, data := range files {
		fsys[name] = &fstest.MapFile{Data: data}
		manifest.Files[name] = rules.Digest(data)
	}
	data, _ := json.Marshal(manifest)
	fsys[rules.ManifestPath] = &fstest.MapFile{Data: data}
	opened, err := Open(fsys, "test")
	if err != nil {
		t.Fatal(err)
	}
	return opened
}

func TestAPackSetLeavesOutChecksFromTheFutureAndCountsThem(t *testing.T) {
	opened := setWithFutureEntries(t)
	if opened.NewerChecks() != 0 {
		t.Fatal("counted checks before any file was read")
	}
	data, err := opened.ReadFile("aws/conflict/generated-aws-1.0.0.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "aws_b") || strings.Contains(string(data), "aws_c") || !strings.Contains(string(data), "aws_a") {
		t.Errorf("the file read = %s", data)
	}
	if got := opened.NewerChecks(); got != 2 {
		t.Errorf("counted %d checks left out, want 2", got)
	}
	// Reading again, from the cache, must not count them again.
	if _, err := opened.ReadFile("aws/conflict/generated-aws-1.0.0.json"); err != nil {
		t.Fatal(err)
	}
	if got := opened.NewerChecks(); got != 2 {
		t.Errorf("counted %d after a second read", got)
	}
}

// A spec is left out like a rule, but it is not one more check to tell the user
// about: the rule that uses it carries its own label.
func TestALookupSpecFromTheFutureIsLeftOutButNotCounted(t *testing.T) {
	opened := setWithFutureEntries(t)
	data, err := opened.ReadFile("aws/lookup/conflict-specs-1.0.0.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "DescribeNew") || !strings.Contains(string(data), `"operation":"Describe"`) {
		t.Errorf("the file read = %s", data)
	}
	if got := opened.NewerChecks(); got != 0 {
		t.Errorf("counted %d for a spec", got)
	}
}

// The bundle check reads every version whole, so a set with entries from the
// future is still accepted: it is only a reader's own reading that leaves them
// out.
func TestAPackSetWithChecksFromTheFutureIsStillAValidSet(t *testing.T) {
	if err := setWithFutureEntries(t).ValidateMaterialized(); err != nil {
		t.Fatal(fmt.Sprint(err))
	}
}
