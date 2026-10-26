package packs

import (
	"slices"
	"testing"
)

// The covered versions are the manifest's, and every per-version pack of a
// covered version is there to read.
func TestCoveredVersionsAreTheManifests(t *testing.T) {
	t.Parallel()
	got, err := AWS()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(got, "6.64.0") {
		t.Fatalf("covered versions %v lack 6.64.0", got)
	}
	for _, version := range got {
		for _, name := range []string{"aws/generated/aws-", "aws/dependency/rules-", "aws/dependency/enforcement-", "aws/lookup/specs-"} {
			if _, err := ReadFile(name + version + ".json"); err != nil {
				t.Errorf("covered version %s: %v", version, err)
			}
		}
	}
	if _, err := ReadFile("aws/dependency/rules-6.64.1.json"); err == nil {
		t.Fatal("a version the packs do not cover was read")
	}
}
