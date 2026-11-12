package aws

import (
	"fmt"
	"testing"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

// groupPlan is a plan with one security group and one other resource whose
// action and type the case sets. vpcExpression is the group's vpc_id as
// Terraform records it in the configuration.
func groupPlan(vpcExpression string, producerType, producerName string, actions string) []byte {
	return []byte(fmt.Sprintf(`{
  "configuration": {"root_module": {"resources": [
    {"address": "aws_security_group.web", "mode": "managed", "type": "aws_security_group", "name": "web", "provider_config_key": "aws",
     "expressions": {"name": {"constant_value": "web"}%s}},
    {"address": "%s.%s", "mode": "managed", "type": "%s", "name": "%s", "provider_config_key": "aws", "expressions": {}}
  ]}},
  "resource_changes": [
    {"address": "aws_security_group.web", "mode": "managed", "type": "aws_security_group", "name": "web",
     "change": {"actions": ["create"], "after": {"name": "web"}, "after_unknown": {"vpc_id": true}}},
    {"address": "%s.%s", "mode": "managed", "type": "%s", "name": "%s",
     "change": {"actions": %s, "after": {}, "after_unknown": {"id": true}}}
  ]
}`, vpcExpression, producerType, producerName, producerType, producerName, producerType, producerName, producerType, producerName, actions))
}

func marked(t *testing.T, plan []byte) bool {
	t.Helper()
	changes := []model.PlannedChange{{Address: "aws_security_group.web", ResourceType: "aws_security_group", Action: model.ActionCreate}}
	return withCreatedHere(changes, plan)[0].CreatedHere["vpc_id"]
}

func TestAVPCCreatedInThePlanIsMarked(t *testing.T) {
	refs := `, "vpc_id": {"references": ["aws_vpc.main.id", "aws_vpc.main"]}`
	for name, actions := range map[string]string{"created": `["create"]`, "replaced": `["delete","create"]`} {
		if !marked(t, groupPlan(refs, "aws_vpc", "main", actions)) {
			t.Errorf("a VPC the plan %s was not marked", name)
		}
	}
}

func TestOnlyANewVPCIsMarked(t *testing.T) {
	refs := `, "vpc_id": {"references": ["aws_vpc.main.id", "aws_vpc.main"]}`
	cases := map[string][]byte{
		"vpc_id not set (the default VPC)":    groupPlan("", "aws_vpc", "main", `["create"]`),
		"a VPC that already exists":           groupPlan(refs, "aws_vpc", "main", `["no-op"]`),
		"a VPC that is only updated":          groupPlan(refs, "aws_vpc", "main", `["update"]`),
		"a variable":                          groupPlan(`, "vpc_id": {"references": ["var.vpc_id"]}`, "aws_vpc", "main", `["create"]`),
		"a data source":                       groupPlan(`, "vpc_id": {"references": ["data.aws_vpc.default.id", "data.aws_vpc.default"]}`, "aws_vpc", "main", `["create"]`),
		"a constant":                          groupPlan(`, "vpc_id": {"constant_value": "vpc-0123456789abcdef0"}`, "aws_vpc", "main", `["create"]`),
		"a subnet's vpc_id, which may be old": groupPlan(`, "vpc_id": {"references": ["aws_subnet.a.vpc_id", "aws_subnet.a"]}`, "aws_subnet", "a", `["create"]`),
		"a resource that is not in the plan":  groupPlan(`, "vpc_id": {"references": ["aws_vpc.other.id", "aws_vpc.other"]}`, "aws_vpc", "main", `["create"]`),
	}
	for name, plan := range cases {
		if marked(t, plan) {
			t.Errorf("%s: marked as a VPC created here", name)
		}
	}
}

func TestAnUnreadablePlanMarksNothing(t *testing.T) {
	if marked(t, []byte("not json")) {
		t.Error("marked from a plan that could not be read")
	}
}
