package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

// planCreatingAGroup is the sg-ingress-literal-peer plan plus a security group
// the same plan creates. Its id is known only after apply, as in any real plan.
func planCreatingAGroup(t *testing.T, plan []byte) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(plan, &document); err != nil {
		t.Fatal(err)
	}
	address := "aws_security_group.web"
	values := map[string]any{"name": "web", "description": "Managed by Terraform", "vpc_id": "vpc-0a1b2c3d4e5f60718"}
	resource := map[string]any{
		"address": address, "mode": "managed", "type": "aws_security_group", "name": "web",
		"provider_name": "registry.terraform.io/hashicorp/aws", "schema_version": 1,
	}
	changes := document["resource_changes"].([]any)
	document["resource_changes"] = append(changes, map[string]any{
		"address": address, "mode": "managed", "type": "aws_security_group", "name": "web",
		"provider_name": "registry.terraform.io/hashicorp/aws",
		"change": map[string]any{
			"actions": []string{"create"}, "before": nil, "after": values,
			"after_unknown": map[string]any{"id": true, "arn": true, "owner_id": true},
		},
	})
	planned := document["planned_values"].(map[string]any)["root_module"].(map[string]any)
	planned["resources"] = append(planned["resources"].([]any), merge(resource, map[string]any{"values": values}))
	configured := document["configuration"].(map[string]any)["root_module"].(map[string]any)
	configured["resources"] = append(configured["resources"].([]any), merge(resource, map[string]any{
		"provider_config_key": "aws",
		"expressions":         map[string]any{"name": map[string]any{"constant_value": "web"}, "vpc_id": map[string]any{"constant_value": "vpc-0a1b2c3d4e5f60718"}},
	}))
	out, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func merge(base, extra map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range base {
		out[key] = value
	}
	for key, value := range extra {
		out[key] = value
	}
	return out
}

// A plan that creates a security group still warns about a literal group id
// that is missing. It was silent (PARTIAL, nothing listed in the short output)
// because the pack could not say where a security group's id comes from, and a
// planned group might have been the one the literal names. AWS picks group
// ids, so it cannot be.
func TestPlanThatCreatesAGroupStillWarnsAboutAMissingLiteralGroup(t *testing.T) {
	copyFixtureWithPeer(t, "testdata/realworld-cases/sg-ingress-literal-peer", absentPeer)
	plan, err := os.ReadFile("plan.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("plan.json", planCreatingAGroup(t, plan), 0o600); err != nil {
		t.Fatal(err)
	}
	isolateAWS(t, true)
	t.Setenv("AWS_ENDPOINT_URL_STS", fakeSTS(t))
	ec2URL, asked := fakeEC2(t, absentPeer)
	t.Setenv("AWS_ENDPOINT_URL_EC2", ec2URL)
	summary, _, document := runRealWorldCheck(t)

	if !packsKnowThePeerRule(t) {
		t.Skip("the packs have no rule for the referenced security group yet")
	}
	assertNothingCheckedNeverPasses(t, summary, document)
	var peer *int
	for index, finding := range document.Findings {
		if finding.ID == "aws.dependency-missing" && finding.Resource == "aws_vpc_security_group_ingress_rule.database_from_shared_services" {
			peer = &index
			if finding.Severity != model.SeverityWarning || finding.Blocking {
				t.Errorf("finding = %+v, want a warning that does not block", finding)
			}
		}
	}
	if peer == nil {
		t.Fatalf("no warning for the missing group; summary:\n%s\nfindings: %+v", summary, document.Findings)
	}
	assertPeerLookup(t, asked(), absentPeer)
}
