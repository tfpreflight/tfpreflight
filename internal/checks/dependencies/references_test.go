package dependencies

import (
	"os"
	"path/filepath"
	"testing"
)

func probePlan(t *testing.T) Plan {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "mixed-references.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := ParsePlan(data)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// This fixture is a real `terraform show -json` from provider 6.64.0, so these
// tests check what Terraform actually records, not an assumption about it.
func TestSamePlanReferenceIsRecognised(t *testing.T) {
	reference := probePlan(t).References["aws_subnet.same_plan"]["vpc_id"]
	if reference.Origin != OriginSamePlan {
		t.Fatalf("origin = %s, want %s", reference.Origin, OriginSamePlan)
	}
	if len(reference.Producers) != 1 || reference.Producers[0] != "aws_vpc.main" {
		t.Fatalf("producers = %v, want [aws_vpc.main]", reference.Producers)
	}
}

func TestLiteralExternalIdentifierIsRecognised(t *testing.T) {
	if origin := probePlan(t).References["aws_subnet.external"]["vpc_id"].Origin; origin != OriginLiteral {
		t.Fatalf("origin = %s, want %s", origin, OriginLiteral)
	}
}

func TestVariableResolvedIdentifierIsRecognised(t *testing.T) {
	plan := probePlan(t)
	if origin := plan.References["aws_security_group_rule.mixed"]["security_group_id"].Origin; origin != OriginVariable {
		t.Fatalf("origin = %s, want %s", origin, OriginVariable)
	}
	if value := plan.Changes["aws_security_group_rule.mixed"].After["security_group_id"]; value != "sg-0123456789abcdef0" {
		t.Fatalf("resolved value = %v", value)
	}
}

// A reference to an attribute other than id still names the producer.
func TestNonIDAttributeReferenceStillNamesTheProducer(t *testing.T) {
	reference := probePlan(t).References["aws_security_group_rule.mixed"]["source_security_group_id"]
	if reference.Origin != OriginSamePlan || len(reference.Producers) != 1 || reference.Producers[0] != "aws_vpc.main" {
		t.Fatalf("reference = %+v", reference)
	}
}

func TestProducerActionsAreRecorded(t *testing.T) {
	actions := probePlan(t).Actions["aws_vpc.main"]
	if len(actions) != 1 || actions[0] != "create" {
		t.Fatalf("actions = %v", actions)
	}
}

// Module-relative references must resolve to module-qualified producers, and
// instance keys must not stop a reference from finding its block.
func TestModuleAndInstanceAddressesResolve(t *testing.T) {
	document := `{
	  "configuration": {"root_module": {"module_calls": {"net": {"module": {"resources": [
	    {"address": "aws_vpc.main", "mode": "managed", "type": "aws_vpc", "name": "main", "expressions": {}},
	    {"address": "aws_subnet.s", "mode": "managed", "type": "aws_subnet", "name": "s",
	     "expressions": {"vpc_id": {"references": ["aws_vpc.main.id", "aws_vpc.main"]}}}
	  ]}}}}},
	  "resource_changes": [
	    {"address": "module.net.aws_vpc.main", "module_address": "module.net", "mode": "managed", "type": "aws_vpc", "name": "main",
	     "change": {"actions": ["create"], "after": {}, "after_unknown": {}}},
	    {"address": "module.net.aws_subnet.s[0]", "module_address": "module.net", "mode": "managed", "type": "aws_subnet", "name": "s",
	     "change": {"actions": ["create"], "after": {}, "after_unknown": {"vpc_id": true}}}
	  ]
	}`
	plan, err := ParsePlan([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	reference := plan.References["module.net.aws_subnet.s[0]"]["vpc_id"]
	if reference.Origin != OriginSamePlan || len(reference.Producers) != 1 || reference.Producers[0] != "module.net.aws_vpc.main" {
		t.Fatalf("reference = %+v", reference)
	}
	if actions := plan.Actions["module.net.aws_vpc.main"]; len(actions) != 1 || actions[0] != "create" {
		t.Fatalf("producer actions = %v", actions)
	}
}

// A local can hide a managed producer; an input variable cannot.
func TestLocalsAreDistinguishedFromVariables(t *testing.T) {
	local := classify("bucket", expression{References: []string{"local.bucket_name"}}, "")
	variable := classify("bucket", expression{References: []string{"var.bucket_name"}}, "")
	if local.Origin != OriginLocal || variable.Origin != OriginVariable {
		t.Fatalf("local = %s, variable = %s", local.Origin, variable.Origin)
	}
}
