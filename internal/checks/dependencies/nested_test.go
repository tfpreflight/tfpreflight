package dependencies

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// nestedRule is the compiled shape of a nested reference: a path through a
// block to a collection of subnet ids.
func nestedRule() ExistenceRule {
	return ExistenceRule{
		Resource: "aws_lambda_function", Operation: "create",
		Attribute: "vpc_config.subnet_ids", Path: []string{"vpc_config", "subnet_ids"},
		Member: "VpcConfig.SubnetIds", Collection: true,
		TargetResource: "aws_subnet", TargetAttribute: "id", TargetIdentity: IdentityServerGenerated,
		Lookup: Lookup{Service: "ec2", Operation: "DescribeSubnets", Field: "SubnetIds", NotFoundCodes: []string{"InvalidSubnetID.NotFound"}},
	}
}

// nestedPlan builds a plan whose consumer holds one vpc_config block.
func nestedPlan(reference AttributeReference, block map[string]any, unknown map[string]any) Plan {
	return Plan{
		References: map[string]map[string]AttributeReference{
			"aws_lambda_function.f": {"vpc_config.subnet_ids": reference},
		},
		Actions: map[string][]string{"aws_subnet.produced": {"no-op"}},
		Changes: map[string]PlannedValues{
			"aws_lambda_function.f": {
				Address: "aws_lambda_function.f", ResourceType: "aws_lambda_function", Actions: []string{"create"},
				After: map[string]any{"vpc_config": []any{block}}, AfterUnknown: map[string]any{"vpc_config": []any{unknown}},
			},
			"aws_subnet.produced": {
				Address: "aws_subnet.produced", ResourceType: "aws_subnet", Actions: []string{"no-op"},
				Before: map[string]any{"id": "subnet-produced"}, After: map[string]any{"id": "subnet-produced"},
			},
		},
		Providers: map[string]string{"aws_lambda_function.f": DefaultProvider},
	}
}

// A nested value the plan produces is never looked up.
func TestNestedSamePlanValueIsNotInspected(t *testing.T) {
	plan := nestedPlan(
		AttributeReference{Attribute: "vpc_config.subnet_ids", Origin: OriginSamePlan, Producers: []string{"aws_subnet.produced"}},
		map[string]any{"subnet_ids": []any{"subnet-produced"}}, map[string]any{"subnet_ids": []any{false}})
	resolver := &fakeResolver{answers: map[string]Existence{"subnet-produced": NotFound}}
	results, coverage := Engine{Existence: []ExistenceRule{nestedRule()}, Resolver: resolver}.Evaluate(context.Background(), plan)
	result := resultFor(t, results, "aws_lambda_function.f")
	if result.Verdict != VerdictSatisfiedByPlan || resolver.calls != 0 {
		t.Fatalf("result = %+v, calls = %d", result, resolver.calls)
	}
	if coverage["aws_lambda_function.f"] != CoverageChecked {
		t.Fatalf("coverage = %s", coverage["aws_lambda_function.f"])
	}
}

// A nested collection holding both a produced value and an external one checks
// only the external one.
func TestNestedMixedValuesCheckOnlyTheExternalOne(t *testing.T) {
	plan := nestedPlan(
		AttributeReference{Attribute: "vpc_config.subnet_ids", Origin: OriginSamePlan, Producers: []string{"aws_subnet.produced"}},
		map[string]any{"subnet_ids": []any{"subnet-produced", "subnet-external"}},
		map[string]any{"subnet_ids": []any{false, false}})
	resolver := &fakeResolver{answers: map[string]Existence{"subnet-external": NotFound, "subnet-produced": NotFound}}
	results, _ := Engine{Existence: []ExistenceRule{nestedRule()}, Resolver: resolver}.Evaluate(context.Background(), plan)
	result := resultFor(t, results, "aws_lambda_function.f")
	if result.Verdict != VerdictViolation || result.Finding == nil {
		t.Fatalf("result = %+v", result)
	}
	if resolver.calls != 1 || !strings.Contains(result.Reason, "subnet-external") {
		t.Fatalf("calls = %d, reason = %s; want only the external id inspected", resolver.calls, result.Reason)
	}
}

// A nested collection that is unknown as a whole may hold values the plan does
// not produce, so it is partial rather than satisfied - and still not looked up.
func TestNestedUnknownCollectionIsPartial(t *testing.T) {
	plan := nestedPlan(
		AttributeReference{Attribute: "vpc_config.subnet_ids", Origin: OriginSamePlan, Producers: []string{"aws_subnet.produced"}},
		map[string]any{}, map[string]any{"subnet_ids": true})
	resolver := &fakeResolver{}
	results, coverage := Engine{Existence: []ExistenceRule{nestedRule()}, Resolver: resolver}.Evaluate(context.Background(), plan)
	result := resultFor(t, results, "aws_lambda_function.f")
	if result.Verdict != VerdictPartial || result.Finding != nil || resolver.calls != 0 {
		t.Fatalf("result = %+v, calls = %d", result, resolver.calls)
	}
	if coverage["aws_lambda_function.f"] != CoveragePartial {
		t.Fatalf("coverage = %s", coverage["aws_lambda_function.f"])
	}
}

// A block that is not configured has nothing to check.
func TestNestedBlockAbsentIsNotApplicable(t *testing.T) {
	plan := Plan{
		References: map[string]map[string]AttributeReference{"aws_lambda_function.f": {}},
		Actions:    map[string][]string{},
		Changes: map[string]PlannedValues{"aws_lambda_function.f": {
			Address:      "aws_lambda_function.f",
			ResourceType: "aws_lambda_function", Actions: []string{"create"},
			After: map[string]any{"vpc_config": []any{}}, AfterUnknown: map[string]any{"vpc_config": []any{}},
		}},
		Providers: map[string]string{"aws_lambda_function.f": DefaultProvider},
	}
	resolver := &fakeResolver{}
	results, coverage := Engine{Existence: []ExistenceRule{nestedRule()}, Resolver: resolver}.Evaluate(context.Background(), plan)
	if result := only(t, results); result.Verdict != VerdictNotApplicable || resolver.calls != 0 {
		t.Fatalf("result = %+v, calls = %d", result, resolver.calls)
	}
	if coverage["aws_lambda_function.f"] != CoverageNoRule {
		t.Fatalf("coverage = %s, want no applicable rule", coverage["aws_lambda_function.f"])
	}
}

// A repeated block answers one path between its instances.
func TestRepeatedBlocksAnswerOnePath(t *testing.T) {
	plan := nestedPlan(
		AttributeReference{Attribute: "vpc_config.subnet_ids", Origin: OriginLiteral},
		map[string]any{"subnet_ids": []any{"subnet-one"}}, map[string]any{"subnet_ids": []any{false}})
	change := plan.Changes["aws_lambda_function.f"]
	change.After = map[string]any{"vpc_config": []any{
		map[string]any{"subnet_ids": []any{"subnet-one"}},
		map[string]any{"subnet_ids": []any{"subnet-two"}},
	}}
	change.AfterUnknown = map[string]any{"vpc_config": []any{
		map[string]any{"subnet_ids": []any{false}}, map[string]any{"subnet_ids": []any{false}},
	}}
	plan.Changes["aws_lambda_function.f"] = change
	resolver := &fakeResolver{answers: map[string]Existence{"subnet-one": Exists, "subnet-two": Exists}}
	results, _ := Engine{Existence: []ExistenceRule{nestedRule()}, Resolver: resolver}.Evaluate(context.Background(), plan)
	if result := resultFor(t, results, "aws_lambda_function.f"); result.Verdict != VerdictSatisfied {
		t.Fatalf("result = %+v", result)
	}
	if resolver.calls != 2 {
		t.Fatalf("inspected %d ids, want both instances", resolver.calls)
	}
}

// An aliased provider is answered without asking AWS, nested or not.
func TestNestedAliasedProviderIsPartial(t *testing.T) {
	plan := nestedPlan(
		AttributeReference{Attribute: "vpc_config.subnet_ids", Origin: OriginLiteral},
		map[string]any{"subnet_ids": []any{"subnet-one"}}, map[string]any{"subnet_ids": []any{false}})
	plan.Providers["aws_lambda_function.f"] = "aws.west"
	resolver := &fakeResolver{answers: map[string]Existence{"subnet-one": NotFound}}
	results, _ := Engine{Existence: []ExistenceRule{nestedRule()}, Resolver: resolver}.Evaluate(context.Background(), plan)
	if result := resultFor(t, results, "aws_lambda_function.f"); result.Verdict != VerdictPartial || result.Finding != nil {
		t.Fatalf("result = %+v", result)
	}
	if resolver.calls != 0 {
		t.Fatalf("inspected the default account for an aliased resource: %d", resolver.calls)
	}
}

// The compiled rules read a real plan: Terraform's own nested expressions and
// planned values decide every verdict below.
func TestCompiledNestedRulesAgainstARealPlan(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "nested-references.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := ParsePlan(data)
	if err != nil {
		t.Fatal(err)
	}
	// Terraform records a nested block's arguments under their own path.
	reference, recorded := plan.References["aws_lambda_function.same_plan"]["vpc_config.subnet_ids"]
	if !recorded || reference.Origin != OriginSamePlan || len(reference.Producers) != 1 {
		t.Fatalf("nested reference = %+v (%v)", reference, recorded)
	}
	// Every lambda also names an IAM role by ARN, a dependency of its own: the
	// role name is read out of the ARN.
	resolver := &fakeResolver{answers: map[string]Existence{
		"subnet-0aaaaaaaaaaaaaaaa": Exists, "sg-0ccccccccccccccc0": Exists, "sg-0ddddddddddddddd0": Exists,
		"probe": Exists,
	}}
	results, coverage := Engine{Existence: compiledRules(t), Resolver: resolver}.Evaluate(context.Background(), plan)

	verdicts := map[string]string{}
	for _, result := range results {
		if result.Verdict != VerdictNotApplicable {
			verdicts[result.Address+" "+strings.SplitN(result.Reason, " is unknown", 2)[0]] = result.Verdict
		}
		if result.Address == "aws_lambda_function.same_plan" && result.Finding != nil {
			t.Fatalf("a target this plan creates was reported: %+v", result)
		}
	}
	// The set holding only produced ids is unknown as a whole, so it is partial
	// rather than satisfied, and it is never inspected.
	if verdicts["aws_lambda_function.same_plan vpc_config.subnet_ids"] != VerdictPartial {
		t.Fatalf("same-plan nested verdicts = %v", verdicts)
	}
	// The literal security group beside a produced subnet is still checked.
	if verdicts["aws_lambda_function.mixed every referenced aws_security_group exists"] != VerdictSatisfied {
		t.Fatalf("mixed nested verdicts = %v", verdicts)
	}
	// The resource without the block still has its role dependency checked.
	if coverage["aws_lambda_function.none"] != CoverageChecked {
		t.Fatalf("a resource without the block = %s", coverage["aws_lambda_function.none"])
	}
	// Three external network identifiers plus one role per function, and
	// nothing produced by the plan.
	if resolver.calls != 7 {
		t.Fatalf("inspections = %d, want the external identifiers and the roles", resolver.calls)
	}
}

// Terraform writes a single block as an object and a repeated block as an
// array; both name the same paths.
func TestNestedExpressionShapes(t *testing.T) {
	for _, shape := range []string{
		`{"vpc_config":{"subnet_ids":{"references":["aws_subnet.a.id"]}}}`,
		`{"vpc_config":[{"subnet_ids":{"references":["aws_subnet.a.id"]}}]}`,
		`{"vpc_config":[{"subnet_ids":{"references":["aws_subnet.a.id"]}},{"subnet_ids":{"constant_value":["subnet-b"]}}]}`,
	} {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal([]byte(shape), &raw); err != nil {
			t.Fatal(err)
		}
		collected := collectExpressions(raw, "", 0)
		expression, found := collected["vpc_config.subnet_ids"]
		if !found || len(expression.References) == 0 {
			t.Fatalf("%s: collected %+v", shape, collected)
		}
	}
	// A deeper block keeps its full path.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(`{"network_configuration":[{"awsvpc_configuration":[{"subnets":{"references":["aws_subnet.a.id"]}}]}]}`), &raw); err != nil {
		t.Fatal(err)
	}
	if _, found := collectExpressions(raw, "", 0)["network_configuration.awsvpc_configuration.subnets"]; !found {
		t.Fatal("a nested block inside a nested block lost its path")
	}
}
