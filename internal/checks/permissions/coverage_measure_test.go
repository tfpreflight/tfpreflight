package permissions

import (
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// How often a create permission's resource ARN can be built: for every
// resource of the 6.64.0 pack, its create permissions, with every name-like
// attribute set to a known value. Logged for the record; it fails only if
// ARN building stopped working altogether.
func TestHowOftenAnARNCanBeBuilt(t *testing.T) {
	pack, loaded, err := packs.LoadRuntimePack(testProviderVersion)
	if err != nil || !loaded {
		t.Fatalf("pack: %v", err)
	}
	known := loadActions()
	counts := map[string]int{}
	for resourceType, resource := range pack.Resources {
		create, ok := resource.Actions["create"]
		if !ok {
			continue
		}
		after := plannedNames(resource.Attributes)
		for _, operation := range create.Operations {
			if operation.Permission == "" {
				continue
			}
			r := plannedPermission{change: model.PlannedChange{ResourceType: resourceType, After: after}, operation: operation, attributes: resource.Attributes, siblings: create.Operations}
			countTarget(counts, targetFor(r, testScope, known), known[strings.ToLower(operation.Permission)])
		}
	}
	total := counts["real ARN"] + counts["action authorized only against *"] + counts["fell back to *"]
	t.Logf("create permissions: %d; real ARN %d, only-* %d, fell back to * %d (of which %d need an ID AWS assigns at create)", total, counts["real ARN"], counts["action authorized only against *"], counts["fell back to *"], counts["needs an ID AWS assigns"])
	if counts["real ARN"] == 0 {
		t.Fatal("no ARN could be built")
	}
}

// plannedNames gives every name-like attribute a value, as a planned create
// with its names set would have.
func plannedNames(attributes []string) map[string]any {
	after := map[string]any{}
	for _, attribute := range attributes {
		if attribute == "name" || strings.HasSuffix(attribute, "_name") || attribute == "bucket" {
			after[attribute] = "example"
		}
	}
	return after
}

// countTarget tallies what simulation target one permission got.
func countTarget(counts map[string]int, target target, action iamAction) {
	switch {
	case target.ARN != "*":
		counts["real ARN"]++
	case target.Exact:
		counts["action authorized only against *"]++
	default:
		counts["fell back to *"]++
		if needsAssignedID(action) {
			counts["needs an ID AWS assigns"]++
		}
	}
}

// needsAssignedID reports whether every ARN the action takes has a variable
// AWS assigns, such as VpcId: unknown before apply whatever the plan says.
func needsAssignedID(action iamAction) bool {
	if len(action.Resources) == 0 {
		return false
	}
	for _, resource := range action.Resources {
		for _, format := range resource.Formats {
			assigned := false
			for _, m := range formatVariable.FindAllStringSubmatch(format, -1) {
				if strings.HasSuffix(m[1], "Id") || strings.HasSuffix(m[1], "ID") {
					assigned = true
				}
			}
			if !assigned {
				return false
			}
		}
	}
	return true
}
