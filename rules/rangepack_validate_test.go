package rules

import (
	"encoding/json"
	"strings"
	"testing"
)

func validTestPack() *RangePack {
	return &RangePack{
		Format: RangePackFormat, Name: "aws/x-{provider_version}.json", Versions: []string{"6.9.0", "6.10.0"},
		Fields: []RangeField{
			{Name: "provider_version", Kind: FieldValue, Present: []VersionRange{{"6.9.0", "6.10.0"}}, Entries: []RangeEntry{{Versions: []VersionRange{{"6.9.0", "6.10.0"}}, Value: json.RawMessage(`"{provider_version}"`)}}},
			{Name: "rules", Kind: FieldList, Present: []VersionRange{{"6.9.0", "6.10.0"}}, Entries: []RangeEntry{
				{Versions: []VersionRange{{"6.9.0", "6.10.0"}}, Value: json.RawMessage(`"a"`)},
				{Versions: []VersionRange{{"6.10.0", "6.10.0"}}, Value: json.RawMessage(`"b"`)},
			}, Order: map[string][]int{"6.10.0": {1, 0}}},
		},
	}
}

// Each structural invariant, broken on its own, is refused with a reason that
// names it; the intact pack passes both levels of validation.
func TestRangePackValidate(t *testing.T) {
	if err := validTestPack().ValidateVersions(); err != nil {
		t.Fatalf("valid pack: %v", err)
	}
	for _, test := range []struct {
		name   string
		damage func(*RangePack)
		want   string
	}{
		{"format", func(p *RangePack) { p.Format = "other/1" }, `format "other/1"`},
		{"name without version token", func(p *RangePack) { p.Name = "aws/x.json" }, "has no {provider_version}"},
		{"no versions", func(p *RangePack) { p.Versions = nil }, "covers no versions"},
		{"repeated version", func(p *RangePack) { p.Versions = []string{"6.9.0", "6.9.0"} }, "not strictly oldest first"},
		{"versions out of order", func(p *RangePack) { p.Versions = []string{"6.10.0", "6.9.0"} }, "not strictly oldest first"},
		{"inexact version", func(p *RangePack) { p.Versions = []string{"6.9", "6.10.0"} }, `version "6.9" is not an exact version`},
		{"unknown kind", func(p *RangePack) { p.Fields[0].Kind = "set" }, `kind "set"`},
		{"repeated field", func(p *RangePack) { p.Fields[1].Name = "provider_version" }, "unnamed or repeated"},
		{"present outside coverage", func(p *RangePack) { p.Fields[0].Present = []VersionRange{{"6.8.0", "6.10.0"}} }, "present: range 6.8.0..6.10.0 names a version"},
		{"backwards range", func(p *RangePack) { p.Fields[1].Entries[0].Versions = []VersionRange{{"6.10.0", "6.9.0"}} }, "runs backwards"},
		{"entry without value", func(p *RangePack) { p.Fields[1].Entries[1].Value = nil }, "entry 1 has no value"},
		{"order for uncovered version", func(p *RangePack) { p.Fields[1].Order = map[string][]int{"7.0.0": {0}} }, "order for 7.0.0"},
		{"order index out of range", func(p *RangePack) { p.Fields[1].Order = map[string][]int{"6.10.0": {2}} }, "names entry 2 of 2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			pack := validTestPack()
			test.damage(pack)
			if err := pack.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() = %v, want %q", err, test.want)
			}
		})
	}
}

// A pack can be structurally sound and still not materialize: a value field
// present in a version with no entry for it. Only full validation finds it.
func TestRangePackValidateVersionsMaterializesEveryVersion(t *testing.T) {
	pack := validTestPack()
	pack.Fields[0].Entries[0].Versions = []VersionRange{{"6.9.0", "6.9.0"}}
	if err := pack.Validate(); err != nil {
		t.Fatalf("structure: %v", err)
	}
	if err := pack.ValidateVersions(); err == nil || !strings.Contains(err.Error(), "provider_version has no value for 6.10.0") {
		t.Fatalf("ValidateVersions() = %v", err)
	}
}
