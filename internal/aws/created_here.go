package aws

import (
	"slices"
	"strings"

	"github.com/tfpreflight/tfpreflight/internal/checks/dependencies"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// scopeResources are the resource types that make a scope, by the attribute
// that names them. Only a VPC is read this way: a rule says "this name is
// unique within a VPC", and a VPC this plan creates holds nothing else yet.
var scopeResources = map[string]string{"vpc_id": "aws_vpc"}

// withCreatedHere marks, on each change, the scope attributes whose value is
// the VPC (or other scope) this same plan creates. It reads what Terraform
// recorded about where the value comes from, so a vpc_id that merely is not
// set, which means the default VPC, is not marked. A plan that cannot be read
// again leaves the changes as they were, and the checks then say "not checked".
func withCreatedHere(changes []model.PlannedChange, planJSON []byte) []model.PlannedChange {
	plan, err := dependencies.ParsePlan(planJSON)
	if err != nil {
		return changes
	}
	out := make([]model.PlannedChange, len(changes))
	copy(out, changes)
	for i, change := range out {
		for attribute, resourceType := range scopeResources {
			if producedHere(plan, change.Address, attribute, resourceType) {
				marked := map[string]bool{}
				for name := range change.CreatedHere {
					marked[name] = true
				}
				marked[attribute] = true
				out[i].CreatedHere = marked
			}
		}
	}
	return out
}

// producedHere reports whether the attribute's value comes only from resources
// of resourceType that this plan creates (or replaces).
func producedHere(plan dependencies.Plan, address, attribute, resourceType string) bool {
	reference, found := plan.References[address][attribute]
	if !found || reference.Origin != dependencies.OriginSamePlan || len(reference.Producers) == 0 {
		return false
	}
	for _, producer := range reference.Producers {
		if producerType(producer) != resourceType || !slices.Contains(plan.Actions[producer], "create") {
			return false
		}
	}
	return true
}

// producerType is the resource type of an address without instance keys, such
// as aws_vpc for module.net.aws_vpc.main.
func producerType(address string) string {
	parts := strings.Split(address, ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-2]
}
