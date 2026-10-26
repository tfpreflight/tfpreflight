package rules_test

import (
	"bytes"
	"io/fs"
	"testing"

	"github.com/tfpreflight/tfpreflight/packs"
	"github.com/tfpreflight/tfpreflight/rules"
)

// Reading and encoding a shipped range pack reproduces the shipped file
// exactly. Re-merging each pack and the per-version digests are checked in
// tests that do not run under the race detector, where merging the largest
// packs takes minutes.
func TestShippedRangePacksAreStable(t *testing.T) {
	for _, name := range shippedRangePacks(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw, err := fs.ReadFile(packs.AWS, name)
			if err != nil {
				t.Fatal(err)
			}
			pack, err := rules.ReadRangePack(raw)
			if err != nil {
				t.Fatal(err)
			}
			assertEncodes(t, "encode", pack, raw)
		})
	}
}

func shippedRangePacks(t *testing.T) []string {
	t.Helper()
	var names []string
	err := fs.WalkDir(packs.AWS, "aws", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		if raw, err := fs.ReadFile(packs.AWS, name); err == nil && rules.IsRangePack(raw) {
			names = append(names, name)
		}
		return nil
	})
	if err != nil || len(names) == 0 {
		t.Fatalf("shipped range packs: %v, %d found", err, len(names))
	}
	return names
}

func assertEncodes(t *testing.T, step string, pack *rules.RangePack, want []byte) {
	t.Helper()
	got, err := pack.Encode()
	if err != nil {
		t.Fatalf("%s: encode: %v", step, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s: encoded pack differs from the shipped file (%d bytes, want %d)", step, len(got), len(want))
	}
}
