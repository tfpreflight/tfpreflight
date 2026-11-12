package packs

import (
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/rules"
)

// beta.6 and every release before beta.7 read pack schema 2 and nothing newer.
const schemaBeforeBeta7 = 2

func TestTheCurrentSchemaIsNewerThanWhatEarlierReleasesRead(t *testing.T) {
	if rules.SchemaVersion <= schemaBeforeBeta7 {
		t.Fatalf("the pack schema is %d. Packs with the listing lookups must carry a schema newer than %d, or an earlier release would read them and run the new lookups the old way", rules.SchemaVersion, schemaBeforeBeta7)
	}
	if rules.OldestSchemaVersion > schemaBeforeBeta7 {
		t.Fatalf("the oldest schema read is %d: a bundle cached before an upgrade would stop being read", rules.OldestSchemaVersion)
	}
}

func TestAnEarlierSchemaIsStillRead(t *testing.T) {
	files := map[string]string{"aws/generated/aws-1.0.0.json": `{"a":1}`, "aws/lookup/specs-1.0.0.json": `{"specs":[]}`}
	manifest := strings.Replace(manifestFor(files), `"schema_version":3`, `"schema_version":2`, 1)
	if !strings.Contains(manifest, `"schema_version":2`) {
		t.Fatal("the test did not write a schema 2 manifest")
	}
	if _, err := Open(set(files, manifest), "test"); err != nil {
		t.Fatalf("a schema 2 pack set was refused: %v", err)
	}
}

func bundleEntries(schemas ...int) rules.Index {
	var list rules.Index
	for i, schema := range schemas {
		list.Bundles = append(list.Bundles, rules.IndexEntry{ID: "b" + string(rune('a'+i)), PackSchemaVersion: schema})
	}
	return list
}

// The index lists the newest bundle first. A reader takes the first it can read
// and names the newer ones it passed over.
func TestEachReleaseTakesTheNewestBundleItCanRead(t *testing.T) {
	list := bundleEntries(3, 2, 2) // the beta.7 bundle, then the two before it
	cases := map[string]struct {
		oldest, newest int
		want           string
		skipped        int
	}{
		"beta.7 reads the newest":                    {2, 3, "ba", 0},
		"beta.6 keeps the bundle it could read":      {2, 2, "bb", 1},
		"a release that reads only schema 3 as well": {3, 3, "ba", 0},
	}
	for name, c := range cases {
		chosen, skipped := chooseBundleReading(list, c.oldest, c.newest)
		if chosen == nil || chosen.ID != c.want || len(skipped) != c.skipped {
			t.Errorf("%s: chose %v, skipped %v; want %s and %d skipped", name, chosen, skipped, c.want, c.skipped)
		}
	}
}

func TestAnEarlierReleaseWithNothingItCanReadSaysSo(t *testing.T) {
	chosen, skipped := chooseBundleReading(bundleEntries(3, 3), 2, 2)
	if chosen != nil || len(skipped) != 2 {
		t.Fatalf("chose %v, skipped %v: with only newer bundles an earlier release must choose none", chosen, skipped)
	}
}

func TestTheCurrentReleaseChoosesWithItsOwnRange(t *testing.T) {
	list := bundleEntries(rules.SchemaVersion+1, rules.SchemaVersion, rules.OldestSchemaVersion)
	chosen, skipped := chooseBundle(list)
	if chosen == nil || chosen.ID != "bb" || len(skipped) != 1 {
		t.Fatalf("chose %v, skipped %v", chosen, skipped)
	}
}
