package rules

import (
	"encoding/json"
	"strings"
	"testing"
)

func capabilityPack() *RangePack {
	all := []VersionRange{{"1.0.0", "2.0.0"}}
	entry := func(value string) RangeEntry { return RangeEntry{Versions: all, Value: json.RawMessage(value)} }
	keyed := func(key, value string) RangeEntry {
		e := entry(value)
		e.Key = key
		return e
	}
	return &RangePack{
		Format: RangePackFormat, Name: "aws/conflict/generated-aws-{provider_version}.json", Versions: []string{"1.0.0", "2.0.0"},
		Fields: []RangeField{
			{Name: "rules", Kind: FieldList, Present: all, Entries: []RangeEntry{
				entry(`{"resource_type":"aws_a"}`),
				entry(`{"resource_type":"aws_b","requires":"listing-lookups"}`),
				entry(`{"resource_type":"aws_c","requires":"a-capability-from-the-future"}`),
				entry(`{"resource_type":"aws_d","note":"the word requires inside text is not a label"}`),
			}},
			{Name: "by_name", Kind: FieldMap, Present: all, Entries: []RangeEntry{
				keyed("x", `{"requires":"a-capability-from-the-future"}`),
				keyed("y", `{"requires":"listing-lookups"}`),
				keyed("z", `"a string value"`),
			}},
		},
	}
}

func materialized(t *testing.T, understands func(string) bool) (string, int) {
	t.Helper()
	data, skipped, err := capabilityPack().MaterializeFor("1.0.0", understands)
	if err != nil {
		t.Fatal(err)
	}
	return string(data), skipped
}

func TestAReaderLeavesOutEntriesNeedingACapabilityItLacks(t *testing.T) {
	out, skipped := materialized(t, KnowsCapability)
	if skipped != 2 {
		t.Errorf("left out %d, want the one rule and the one map entry", skipped)
	}
	for _, gone := range []string{"aws_c", `"x"`} {
		if strings.Contains(out, gone) {
			t.Errorf("an entry needing a capability from the future is still there (%s): %s", gone, out)
		}
	}
	for _, kept := range []string{"aws_a", "aws_b", "aws_d", `"y"`, `"z"`} {
		if !strings.Contains(out, kept) {
			t.Errorf("an entry this version can run was left out (%s): %s", kept, out)
		}
	}
	var parsed any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Errorf("the pack is no longer valid JSON: %v\n%s", err, out)
	}
}

func TestAReaderThatKnowsNoCapabilityLeavesOutEveryLabelledEntry(t *testing.T) {
	out, skipped := materialized(t, func(string) bool { return false })
	if skipped != 4 || strings.Contains(out, "aws_b") || strings.Contains(out, "aws_c") {
		t.Errorf("left out %d: %s", skipped, out)
	}
}

// The builder reads packs whole. Only a reader that gives a capability test
// leaves anything out.
func TestMaterializeStillGivesEveryEntry(t *testing.T) {
	data, err := capabilityPack().Materialize("1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"aws_a", "aws_b", "aws_c", "aws_d", `"x"`, `"y"`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("Materialize left out %s", want)
		}
	}
}

func TestLeavingOutRespectsAnExplicitOrder(t *testing.T) {
	pack := capabilityPack()
	pack.Fields[0].Order = map[string][]int{"1.0.0": {3, 2, 1, 0}}
	data, skipped, err := pack.MaterializeFor("1.0.0", KnowsCapability)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Rules []struct {
			Resource string `json:"resource_type"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("%v\n%s", err, data)
	}
	var got []string
	for _, rule := range parsed.Rules {
		got = append(got, rule.Resource)
	}
	if skipped != 2 || strings.Join(got, ",") != "aws_d,aws_b,aws_a" {
		t.Errorf("rules %v, left out %d: the order given must hold with the future rule removed", got, skipped)
	}
}

func TestOnlyTheListingCapabilityIsKnownToday(t *testing.T) {
	if !KnowsCapability(CapabilityListingLookups) || KnowsCapability("") || KnowsCapability("a-capability-from-the-future") {
		t.Error("the set of known capabilities is wrong")
	}
}

// A spec from the future may use a protocol or a field this version cannot
// judge. Checking it would refuse a whole pack set over something never sent.
func TestASpecFromTheFutureIsNotJudgedByTheReadOnlyCheck(t *testing.T) {
	future := Spec{Service: "x", Operation: "Delete", Protocol: "a-protocol-from-the-future", Requires: "a-capability-from-the-future"}
	if err := (SpecSet{Specs: []Spec{future}}).Check(); err != nil {
		t.Errorf("a spec this version will never send was judged: %v", err)
	}
	future.Requires = ""
	if err := (SpecSet{Specs: []Spec{future}}).Check(); err == nil {
		t.Error("a spec with an unknown protocol and no capability label was accepted")
	}
	// A label this version knows does not excuse a spec from the check.
	known := Spec{Service: "x", Operation: "Delete", Protocol: "a-protocol-from-the-future", Requires: CapabilityListingLookups}
	if err := (SpecSet{Specs: []Spec{known}}).Check(); err == nil {
		t.Error("a spec this version runs was not checked")
	}
}
