package packs

import (
	"testing"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

// The reviewed conditions decide, from the plan, operations the generated rules
// could only call possible.
func TestReviewedConditionsDecideFromThePlan(t *testing.T) {
	pack, _, err := LoadRuntimePack(testProviderVersion)
	if err != nil {
		t.Fatal(err)
	}
	vpcDefaults := map[string]any{"enable_dns_hostnames": false, "enable_dns_support": true, "enable_network_address_usage_metrics": false}
	with := func(field string, value any) map[string]any {
		changed := map[string]any{}
		for key, existing := range vpcDefaults {
			changed[key] = existing
		}
		changed[field] = value
		return changed
	}
	for name, tc := range map[string]struct {
		resource, operation string
		after, unknown      map[string]any
		runs                bool
	}{
		"VPC with defaults":            {"aws_vpc", "ec2:ModifyVpcAttribute", vpcDefaults, nil, false},
		"VPC with DNS hostnames":       {"aws_vpc", "ec2:ModifyVpcAttribute", with("enable_dns_hostnames", true), nil, true},
		"VPC without DNS support":      {"aws_vpc", "ec2:ModifyVpcAttribute", with("enable_dns_support", false), nil, true},
		"VPC with usage metrics":       {"aws_vpc", "ec2:ModifyVpcAttribute", with("enable_network_address_usage_metrics", true), nil, true},
		"VPC attribute known at apply": {"aws_vpc", "ec2:ModifyVpcAttribute", with("enable_dns_hostnames", nil), map[string]any{"enable_dns_hostnames": true}, true},
		"group membership with users":  {"aws_iam_group_membership", "iam:AddUserToGroup", map[string]any{"users": []any{"alice"}}, nil, true},
		"group membership, no users":   {"aws_iam_group_membership", "iam:AddUserToGroup", map[string]any{"users": []any{}}, nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			change := model.PlannedChange{ResourceType: tc.resource, Action: model.ActionCreate, After: tc.after, AfterUnknown: tc.unknown}
			operation, found := createOperation(pack, tc.resource, tc.operation)
			if !found {
				t.Fatalf("%s has no %s operation in the %s pack", tc.resource, tc.operation, testProviderVersion)
			}
			if !operation.ConditionEvaluable() {
				t.Fatalf("%s is still undecidable: %+v", tc.operation, operation.Condition)
			}
			if got := operation.WillRun(change); got != tc.runs {
				t.Fatalf("WillRun = %v, want %v", got, tc.runs)
			}
		})
	}
}

func createOperation(pack KnowledgePack, resource, name string) (OperationRule, bool) {
	for _, operation := range pack.Resources[resource].Actions["create"].Operations {
		if operation.Service+":"+operation.Name == name {
			return operation, true
		}
	}
	return OperationRule{}, false
}
