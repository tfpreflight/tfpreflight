package packs

import (
	"slices"
	"testing"

	"github.com/tfpreflight/tfpreflight/rules"
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

// The release after the newest covered one is newer than every pack, and is
// not covered itself.
func TestNewerThanCoveredIsBeyondEveryPack(t *testing.T) {
	t.Parallel()
	newer, err := NewerThanCovered()
	if err != nil {
		t.Fatal(err)
	}
	versions, err := AWS()
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range versions {
		if rules.CompareVersions(newer, version) <= 0 {
			t.Fatalf("%s is not newer than covered version %s", newer, version)
		}
	}
	if _, loaded, err := LoadRuntimePack(newer); err != nil || loaded {
		t.Fatalf("%s: loaded=%v err=%v, want not covered", newer, loaded, err)
	}
}

// The release before the oldest covered one is older than every pack, and is
// not covered itself.
func TestOlderThanCoveredIsBelowEveryPack(t *testing.T) {
	t.Parallel()
	older, err := OlderThanCovered()
	if err != nil {
		t.Fatal(err)
	}
	versions, err := AWS()
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range versions {
		if rules.CompareVersions(older, version) >= 0 {
			t.Fatalf("%s is not older than covered version %s", older, version)
		}
	}
	if _, loaded, err := LoadRuntimePack(older); err != nil || loaded {
		t.Fatalf("%s: loaded=%v err=%v, want not covered", older, loaded, err)
	}
}
