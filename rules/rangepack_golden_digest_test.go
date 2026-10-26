//go:build !race

package rules_test

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/packs"
	"github.com/tfpreflight/tfpreflight/rules"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite testdata/rangepack-materialize.golden from the shipped packs")

const materializeGolden = "testdata/rangepack-materialize.golden"

// Every covered version of every shipped range pack materializes to the
// bytes recorded in testdata. A pack update regenerates the record with
// -update-golden.
func TestShippedRangePacksAreStableDigests(t *testing.T) {
	digests := map[string]string{}
	for _, name := range shippedRangePacks(t) {
		_, _, docs := materializeShipped(t, name)
		for version, doc := range docs {
			digests[name+" "+version] = sha256Hex(doc)
		}
	}
	if *updateGolden {
		writeGolden(t, digests)
		return
	}
	compareGolden(t, digests, readGolden(t))
}

// materializeShipped reads one shipped range pack and materializes every
// version it covers.
func materializeShipped(t *testing.T, name string) ([]byte, *rules.RangePack, map[string][]byte) {
	t.Helper()
	raw, err := fs.ReadFile(packs.AWS, name)
	if err != nil {
		t.Fatal(err)
	}
	pack, err := rules.ReadRangePack(raw)
	if err != nil {
		t.Fatal(err)
	}
	docs := map[string][]byte{}
	for _, version := range pack.Versions {
		doc, err := pack.Materialize(version)
		if err != nil {
			t.Fatalf("materialize %s: %v", version, err)
		}
		docs[version] = doc
	}
	return raw, pack, docs
}

func readGolden(t *testing.T) map[string]string {
	t.Helper()
	data, err := os.ReadFile(materializeGolden)
	if err != nil {
		t.Fatalf("%v (run go test ./rules -run TestShippedRangePacksAreStable -update-golden)", err)
	}
	want := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		key, digest, _ := strings.Cut(line, "  ")
		want[key] = digest
	}
	return want
}

func compareGolden(t *testing.T, got, want map[string]string) {
	t.Helper()
	for key, digest := range want {
		if got[key] != digest {
			t.Errorf("%s materializes to sha256 %s, golden has %s", key, got[key], digest)
		}
	}
	for key := range got {
		if _, ok := want[key]; !ok {
			t.Errorf("%s is not in %s", key, materializeGolden)
		}
	}
}

func writeGolden(t *testing.T, digests map[string]string) {
	t.Helper()
	lines := make([]string, 0, len(digests))
	for key, digest := range digests {
		lines = append(lines, fmt.Sprintf("%s  %s", key, digest))
	}
	sort.Strings(lines)
	if err := os.WriteFile(materializeGolden, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
