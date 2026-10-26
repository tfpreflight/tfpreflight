package conflicts

import (
	"sort"
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/packs"
)

// builtInConflictTypes are the resource types the built-in checks (bucket and
// IAM name) handle: every type whose runtime pack carries a conflict rule on any
// action.
func builtInConflictTypes(t *testing.T) map[string]bool {
	t.Helper()
	pack, loaded, err := packs.LoadRuntimePack(testProviderVersion)
	if err != nil || !loaded {
		t.Fatalf("load runtime pack: loaded=%v err=%v", loaded, err)
	}
	types := map[string]bool{}
	for resourceType, resource := range pack.Resources {
		for _, action := range resource.Actions {
			if action.Conflict != nil {
				types[resourceType] = true
			}
		}
	}
	return types
}

// resolverConflictTypes are the resource types the generated resolver checks:
// every type in the curated or generated conflict pack.
func resolverConflictTypes(t *testing.T) map[string]bool {
	t.Helper()
	rules, err := loadConflictRules(testProviderVersion)
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]bool{}
	for _, rule := range rules {
		types[rule.ResourceType] = true
	}
	return types
}

// A resource type checked by both paths gets one conflict finding from each,
// with different IDs and severities for the same collision. Every type must
// have exactly one source.
func TestEveryConflictTypeHasOneSource(t *testing.T) {
	builtIn, resolver := builtInConflictTypes(t), resolverConflictTypes(t)
	if len(builtIn) == 0 || len(resolver) == 0 {
		t.Fatalf("built-in=%d resolver=%d; both should cover something", len(builtIn), len(resolver))
	}
	var both []string
	for resourceType := range builtIn {
		if resolver[resourceType] {
			both = append(both, resourceType)
		}
	}
	sort.Strings(both)
	if len(both) > 0 {
		t.Fatalf("checked by both the built-in checks and the generated resolver: %v; remove them from the built-in checks", both)
	}
}

// The built-in checks should only shrink. A type added to them must be one the
// resolver cannot express, and that is a deliberate decision made here.
func TestBuiltInConflictChecksCoverOnlyWhatTheResolverCannot(t *testing.T) {
	var got []string
	for resourceType := range builtInConflictTypes(t) {
		got = append(got, resourceType)
	}
	sort.Strings(got)
	want := []string{"aws_iam_role", "aws_s3_bucket"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("built-in conflict types = %v, want %v", got, want)
	}
}
