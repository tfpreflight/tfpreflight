package packs

// reviewedConditions decide operations the generated rules leave as
// control-flow conditions the plan cannot test. Each was read by hand from the
// provider's create function (terraform-provider-aws v6.68.0) and names the
// planned values that make the create call the operation.
var reviewedConditions = map[string]map[string]OperationCondition{
	// resourceGroupMembershipCreate calls AddUserToGroup once per user.
	"aws_iam_group_membership": {
		"iam:AddUserToGroup": {Type: ConditionAttributeSet, Field: "users"},
	},
	// modifyVPCAttributesOnCreate calls ModifyVpcAttribute for each attribute
	// that differs from a new VPC's: DNS hostnames off, DNS support on, and
	// network address usage metrics off.
	"aws_vpc": {
		"ec2:ModifyVpcAttribute": {Type: ConditionAnyEquals, Equals: map[string]any{
			"enable_dns_hostnames":                 true,
			"enable_dns_support":                   false,
			"enable_network_address_usage_metrics": true,
		}},
	},
}

// applyReviewedConditions replaces the generated condition of each reviewed
// create operation that the plan could not decide.
func applyReviewedConditions(pack *KnowledgePack) {
	for resourceType, operations := range reviewedConditions {
		action, found := pack.Resources[resourceType].Actions["create"]
		if !found {
			continue
		}
		for index, operation := range action.Operations {
			condition, reviewed := operations[operation.Service+":"+operation.Name]
			if reviewed && operation.Certainty == CertaintyConditional && !operation.ConditionEvaluable() {
				action.Operations[index].Condition = &condition
			}
		}
		pack.Resources[resourceType].Actions["create"] = action
	}
}
