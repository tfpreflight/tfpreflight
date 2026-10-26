package dependencies

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeResolver struct {
	answers map[string]Existence
	calls   int
}

func (f *fakeResolver) Exists(_ context.Context, _ Lookup, _ Scope, identifier string) (Existence, string) {
	f.calls++
	if answer, ok := f.answers[identifier]; ok {
		return answer, "fake"
	}
	return Unknown, "AccessDenied"
}

func subnetRule() ExistenceRule {
	return ExistenceRule{
		Resource: "aws_subnet", Operation: "create", Attribute: "vpc_id",
		TargetResource: "aws_vpc", TargetAttribute: "id", TargetIdentity: IdentityServerGenerated,
		Lookup: Lookup{Service: "ec2", Operation: "DescribeVpcs", Field: "VpcIds", NotFoundCodes: []string{"InvalidVpcID.NotFound"}},
	}
}

func subnetPlan(origin string, value any, unknown any, producers ...string) Plan {
	return Plan{
		References: map[string]map[string]AttributeReference{
			"aws_subnet.s": {"vpc_id": {Attribute: "vpc_id", Origin: origin, Producers: producers}},
		},
		Actions: map[string][]string{"aws_vpc.main": {"create"}},
		Changes: map[string]PlannedValues{
			"aws_subnet.s": {
				Address: "aws_subnet.s", ResourceType: "aws_subnet", Actions: []string{"create"},
				After: map[string]any{"vpc_id": value}, AfterUnknown: map[string]any{"vpc_id": unknown},
			},
		},
		Providers: map[string]string{"aws_subnet.s": DefaultProvider},
	}
}

func only(t *testing.T, results []Result) Result {
	t.Helper()
	if len(results) != 1 {
		t.Fatalf("results = %#v, want exactly one", results)
	}
	return results[0]
}

func TestExternalDependencyThatExistsProducesNoFinding(t *testing.T) {
	resolver := &fakeResolver{answers: map[string]Existence{"vpc-1": Exists}}
	results, _ := Engine{Existence: []ExistenceRule{subnetRule()}, Resolver: resolver}.Evaluate(context.Background(), subnetPlan(OriginLiteral, "vpc-1", nil))
	result := only(t, results)
	if result.Verdict != VerdictSatisfied || result.Finding != nil {
		t.Fatalf("result = %+v", result)
	}
}

func TestExternalDependencyThatIsMissingIsAViolation(t *testing.T) {
	resolver := &fakeResolver{answers: map[string]Existence{"vpc-gone": NotFound}}
	results, coverage := Engine{Existence: []ExistenceRule{subnetRule()}, Resolver: resolver}.Evaluate(context.Background(), subnetPlan(OriginLiteral, "vpc-gone", nil))
	result := only(t, results)
	if result.Verdict != VerdictViolation || result.Finding == nil {
		t.Fatalf("result = %+v", result)
	}
	if coverage["aws_subnet.s"] != CoverageChecked {
		t.Fatalf("coverage = %s", coverage["aws_subnet.s"])
	}
}

// The false finding this engine exists to avoid: a parent the same plan
// creates is absent before apply by design.
func TestDependencyCreatedInTheSamePlanIsNotReportedMissing(t *testing.T) {
	resolver := &fakeResolver{answers: map[string]Existence{}}
	results, _ := Engine{Existence: []ExistenceRule{subnetRule()}, Resolver: resolver}.Evaluate(context.Background(),
		subnetPlan(OriginSamePlan, nil, true, "aws_vpc.main"))
	result := only(t, results)
	if result.Verdict != VerdictSatisfiedByPlan || result.Finding != nil {
		t.Fatalf("result = %+v", result)
	}
	if resolver.calls != 0 {
		t.Fatal("AWS must not be asked about a target the plan creates")
	}
}

func TestUnknownDependencyIdentifierIsPartial(t *testing.T) {
	results, coverage := Engine{Existence: []ExistenceRule{subnetRule()}, Resolver: &fakeResolver{}}.Evaluate(context.Background(),
		subnetPlan(OriginVariable, nil, true))
	if result := only(t, results); result.Verdict != VerdictPartial || result.Finding != nil {
		t.Fatalf("result = %+v", result)
	}
	if coverage["aws_subnet.s"] != CoveragePartial {
		t.Fatalf("coverage = %s", coverage["aws_subnet.s"])
	}
}

// An unreadable lookup is never absence.
func TestInspectionAccessDeniedIsPartial(t *testing.T) {
	results, _ := Engine{Existence: []ExistenceRule{subnetRule()}, Resolver: &fakeResolver{}}.Evaluate(context.Background(),
		subnetPlan(OriginLiteral, "vpc-1", nil))
	if result := only(t, results); result.Verdict != VerdictPartial || result.Finding != nil {
		t.Fatalf("result = %+v", result)
	}
}

// A lookup that cannot prove absence may confirm existence but never report a
// target missing, whatever the resolver says.
func TestLookupWithoutAbsenceSemanticsCannotReportMissing(t *testing.T) {
	rule := subnetRule()
	rule.Lookup.NotFoundCodes = nil
	resolver := &fakeResolver{answers: map[string]Existence{"vpc-gone": NotFound}}
	results, _ := Engine{Existence: []ExistenceRule{rule}, Resolver: resolver}.Evaluate(context.Background(), subnetPlan(OriginLiteral, "vpc-gone", nil))
	if result := only(t, results); result.Verdict != VerdictPartial || result.Finding != nil {
		t.Fatalf("result = %+v", result)
	}
}

// A literal can name a target this plan creates without referencing it.
// Terraform then orders nothing, which is a real risk but not a missing target.
func TestLiteralMatchingAPlannedCreateIsAnOrderingRisk(t *testing.T) {
	rule := ExistenceRule{
		Resource: "aws_lambda_function", Operation: "create", Attribute: "role",
		TargetResource: "aws_iam_role", TargetAttribute: "name", TargetIdentity: "name",
		Lookup: Lookup{Service: "iam", Operation: "GetRole", Field: "RoleName", NotFoundType: "NoSuchEntityException"},
	}
	plan := Plan{
		References: map[string]map[string]AttributeReference{"aws_lambda_function.f": {"role": {Attribute: "role", Origin: OriginLiteral}}},
		Actions:    map[string][]string{},
		Changes: map[string]PlannedValues{
			"aws_lambda_function.f": {
				Address: "aws_lambda_function.f", ResourceType: "aws_lambda_function", Actions: []string{"create"},
				After: map[string]any{"role": "app"}, AfterUnknown: map[string]any{},
			},
			"aws_iam_role.r": {
				Address: "aws_iam_role.r", ResourceType: "aws_iam_role", Actions: []string{"create"},
				After: map[string]any{"name": "app"}, AfterUnknown: map[string]any{},
			},
		},
		Providers: map[string]string{"aws_lambda_function.f": DefaultProvider},
	}
	resolver := &fakeResolver{answers: map[string]Existence{"app": NotFound}}
	results, _ := Engine{Existence: []ExistenceRule{rule}, Resolver: resolver}.Evaluate(context.Background(), plan)
	var found *Result
	for index := range results {
		if results[index].Address == "aws_lambda_function.f" {
			found = &results[index]
		}
	}
	if found == nil || found.Verdict != VerdictOrderingRisk {
		t.Fatalf("result = %+v, want an ordering risk rather than a missing target", found)
	}
}

// When the target's id source is unknown and the plan creates that type, a
// literal cannot be ruled out as one of them.
func TestUndecidableSamePlanCreateIsPartial(t *testing.T) {
	rule := subnetRule()
	rule.TargetIdentity = IdentityUnknown
	plan := subnetPlan(OriginLiteral, "vpc-gone", nil)
	plan.Changes["aws_vpc.other"] = PlannedValues{Address: "aws_vpc.other", ResourceType: "aws_vpc", Actions: []string{"create"}, After: map[string]any{}}
	resolver := &fakeResolver{answers: map[string]Existence{"vpc-gone": NotFound}}
	results, _ := Engine{Existence: []ExistenceRule{rule}, Resolver: resolver}.Evaluate(context.Background(), plan)
	for _, result := range results {
		if result.Address == "aws_subnet.s" && result.Verdict != VerdictPartial {
			t.Fatalf("result = %+v, want partial", result)
		}
	}
}

// A literal naming something this plan destroys exists today but is not ordered
// after the create.
func TestLiteralNamingADestroyedTargetIsAnOrderingRisk(t *testing.T) {
	plan := subnetPlan(OriginLiteral, "vpc-old", nil)
	plan.Changes["aws_vpc.old"] = PlannedValues{
		Address: "aws_vpc.old", ResourceType: "aws_vpc", Actions: []string{"delete"},
		Before: map[string]any{"id": "vpc-old"},
	}
	resolver := &fakeResolver{answers: map[string]Existence{"vpc-old": Exists}}
	results, _ := Engine{Existence: []ExistenceRule{subnetRule()}, Resolver: resolver}.Evaluate(context.Background(), plan)
	for _, result := range results {
		if result.Address == "aws_subnet.s" && result.Verdict != VerdictOrderingRisk {
			t.Fatalf("result = %+v, want an ordering risk", result)
		}
	}
}

func TestNoRuleIsNotReportedAsChecked(t *testing.T) {
	plan := subnetPlan(OriginLiteral, "vpc-1", nil)
	_, coverage := Engine{}.Evaluate(context.Background(), plan)
	if coverage["aws_subnet.s"] != CoverageNoRule {
		t.Fatalf("coverage = %s, want %s", coverage["aws_subnet.s"], CoverageNoRule)
	}
}

// A lookup runs in the default provider configuration's account and region.
// A resource that uses another configuration cannot be checked there, and a
// miss would prove nothing.
func TestAliasedProviderConfigurationIsPartial(t *testing.T) {
	plan := subnetPlan(OriginLiteral, "vpc-1", nil)
	plan.Providers["aws_subnet.s"] = "aws.west"
	resolver := &fakeResolver{answers: map[string]Existence{"vpc-1": NotFound}}
	results, _ := Engine{Existence: []ExistenceRule{subnetRule()}, Resolver: resolver}.Evaluate(context.Background(), plan)
	if result := only(t, results); result.Verdict != VerdictPartial || result.Finding != nil {
		t.Fatalf("result = %+v, want partial without a finding", result)
	}
	if resolver.calls != 0 {
		t.Fatalf("resolver called %d times for a lookup in the wrong account or region", resolver.calls)
	}
}

// peer_vpc_id with peer_region set names a VPC in another region. Unset, the
// peer is local and the lookup is valid.
func TestScopeArgumentDecidesWhetherTheLookupApplies(t *testing.T) {
	rule := ExistenceRule{
		Resource: "aws_vpc_peering_connection", Operation: "create", Attribute: "peer_vpc_id",
		TargetResource: "aws_vpc", TargetAttribute: "id", TargetIdentity: IdentityServerGenerated,
		ScopeAttributes: []string{"peer_owner_id", "peer_region"},
		Lookup:          Lookup{Service: "ec2", Operation: "DescribeVpcs", Field: "VpcIds", NotFoundCodes: []string{"InvalidVpcID.NotFound"}},
	}
	plan := func(scoped bool) Plan {
		references := map[string]AttributeReference{"peer_vpc_id": {Attribute: "peer_vpc_id", Origin: OriginLiteral}}
		if scoped {
			references["peer_region"] = AttributeReference{Attribute: "peer_region", Origin: OriginLiteral}
		}
		return Plan{
			References: map[string]map[string]AttributeReference{"aws_vpc_peering_connection.p": references},
			Actions:    map[string][]string{},
			Changes: map[string]PlannedValues{"aws_vpc_peering_connection.p": {
				Address:      "aws_vpc_peering_connection.p",
				ResourceType: "aws_vpc_peering_connection", Actions: []string{"create"},
				After: map[string]any{"peer_vpc_id": "vpc-peer"}, AfterUnknown: map[string]any{},
			}},
			Providers: map[string]string{"aws_vpc_peering_connection.p": DefaultProvider},
		}
	}
	resolver := &fakeResolver{answers: map[string]Existence{"vpc-peer": NotFound}}
	engine := Engine{Existence: []ExistenceRule{rule}, Resolver: resolver}
	results, _ := engine.Evaluate(context.Background(), plan(true))
	if result := only(t, results); result.Verdict != VerdictPartial || result.Finding != nil || resolver.calls != 0 {
		t.Fatalf("scoped: result = %+v, calls = %d; want partial without asking AWS", result, resolver.calls)
	}
	results, _ = engine.Evaluate(context.Background(), plan(false))
	if result := only(t, results); result.Verdict != VerdictViolation {
		t.Fatalf("unscoped: result = %+v, want a violation for a missing local peer", result)
	}
}

func bucketRule() ExistenceRule {
	return ExistenceRule{
		Resource: "aws_s3_bucket_policy", Operation: "create", Attribute: "bucket",
		TargetResource: "aws_s3_bucket", TargetAttribute: "id", TargetIdentity: "bucket",
		Lookup: Lookup{Service: "s3", Operation: "HeadBucket", Field: "Bucket", NotFoundType: "NotFound"},
	}
}

// bucketPlan creates bucket "logs" and a policy whose bucket value arrives by
// the given origin.
func bucketPlan(origin string, producers ...string) Plan {
	return Plan{
		References: map[string]map[string]AttributeReference{
			"aws_s3_bucket_policy.p": {"bucket": {Attribute: "bucket", Origin: origin, Producers: producers}},
		},
		Actions: map[string][]string{"aws_s3_bucket.b": {"create"}},
		Changes: map[string]PlannedValues{
			"aws_s3_bucket.b": {
				Address: "aws_s3_bucket.b", ResourceType: "aws_s3_bucket", Actions: []string{"create"},
				After: map[string]any{"bucket": "logs"}, AfterUnknown: map[string]any{"id": true},
			},
			"aws_s3_bucket_policy.p": {
				Address: "aws_s3_bucket_policy.p", ResourceType: "aws_s3_bucket_policy", Actions: []string{"create"},
				After: map[string]any{"bucket": "logs"}, AfterUnknown: map[string]any{},
			},
		},
		Providers: map[string]string{"aws_s3_bucket_policy.p": DefaultProvider},
	}
}

// bucket = aws_s3_bucket.b.bucket is known at plan time, yet it names the
// bucket this plan creates. Looking it up would report it missing.
func TestKnownNameFromASamePlanProducerIsNotLookedUp(t *testing.T) {
	resolver := &fakeResolver{answers: map[string]Existence{"logs": NotFound}}
	results, _ := Engine{Existence: []ExistenceRule{bucketRule()}, Resolver: resolver}.Evaluate(context.Background(), bucketPlan(OriginSamePlan, "aws_s3_bucket.b"))
	result := resultFor(t, results, "aws_s3_bucket_policy.p")
	if result.Verdict != VerdictSatisfiedByPlan || resolver.calls != 0 {
		t.Fatalf("result = %+v, calls = %d; want satisfied by plan without asking AWS", result, resolver.calls)
	}
}

// A local or module output can carry the same name without the plan saying
// where it came from. A planned create holding it makes the check partial.
func TestIndirectValueMatchingAPlannedCreateIsPartial(t *testing.T) {
	for _, origin := range []string{OriginLocal, OriginModuleOutput, OriginUnknown} {
		resolver := &fakeResolver{answers: map[string]Existence{"logs": NotFound}}
		results, _ := Engine{Existence: []ExistenceRule{bucketRule()}, Resolver: resolver}.Evaluate(context.Background(), bucketPlan(origin))
		result := resultFor(t, results, "aws_s3_bucket_policy.p")
		if result.Verdict != VerdictPartial || result.Finding != nil || resolver.calls != 0 {
			t.Fatalf("%s: result = %+v, calls = %d; want partial without asking AWS", origin, result, resolver.calls)
		}
	}
}

// A set that is unknown as a whole may hold literals beside the planned ids;
// the plan does not show them, so the check is partial, not satisfied.
func TestUnknownSamePlanCollectionIsPartial(t *testing.T) {
	rule := subnetRule()
	rule.Resource, rule.Attribute, rule.Collection = "aws_db_subnet_group", "subnet_ids", true
	plan := Plan{
		References: map[string]map[string]AttributeReference{
			"aws_db_subnet_group.g": {"subnet_ids": {Attribute: "subnet_ids", Origin: OriginSamePlan, Producers: []string{"aws_subnet.a"}}},
		},
		Actions: map[string][]string{"aws_subnet.a": {"create"}},
		Changes: map[string]PlannedValues{
			"aws_db_subnet_group.g": {
				Address: "aws_db_subnet_group.g", ResourceType: "aws_db_subnet_group", Actions: []string{"create"},
				AfterUnknown: map[string]any{"subnet_ids": true},
			},
		},
		Providers: map[string]string{"aws_db_subnet_group.g": DefaultProvider},
	}
	resolver := &fakeResolver{}
	results, _ := Engine{Existence: []ExistenceRule{rule}, Resolver: resolver}.Evaluate(context.Background(), plan)
	if result := only(t, results); result.Verdict != VerdictPartial || resolver.calls != 0 {
		t.Fatalf("result = %+v, calls = %d", result, resolver.calls)
	}
}

// A same-plan expression can still yield a literal, as in
// var.create ? aws_vpc.main.id : "vpc-x". A known value no producer plans is
// an external identifier and is checked.
func TestKnownValueNoProducerPlansIsChecked(t *testing.T) {
	plan := subnetPlan(OriginSamePlan, "vpc-x", nil, "aws_vpc.main")
	plan.Changes["aws_vpc.main"] = PlannedValues{
		Address: "aws_vpc.main", ResourceType: "aws_vpc", Actions: []string{"create"},
		After: map[string]any{"cidr_block": "10.0.0.0/16"}, AfterUnknown: map[string]any{"id": true},
	}
	resolver := &fakeResolver{answers: map[string]Existence{"vpc-x": NotFound}}
	results, _ := Engine{Existence: []ExistenceRule{subnetRule()}, Resolver: resolver}.Evaluate(context.Background(), plan)
	if result := resultFor(t, results, "aws_subnet.s"); result.Verdict != VerdictViolation || resolver.calls != 1 {
		t.Fatalf("result = %+v, calls = %d; want the literal checked and found missing", result, resolver.calls)
	}
}

// In a known list, only the elements no producer accounts for are checked.
func TestKnownListChecksOnlyUnproducedElements(t *testing.T) {
	rule := subnetRule()
	rule.Resource, rule.Attribute, rule.Collection = "aws_db_subnet_group", "subnet_ids", true
	plan := Plan{
		References: map[string]map[string]AttributeReference{
			"aws_db_subnet_group.g": {"subnet_ids": {Attribute: "subnet_ids", Origin: OriginSamePlan, Producers: []string{"aws_subnet.a"}}},
		},
		Actions: map[string][]string{"aws_subnet.a": {"no-op"}},
		Changes: map[string]PlannedValues{
			"aws_subnet.a": {
				Address: "aws_subnet.a", ResourceType: "aws_subnet", Actions: []string{"no-op"},
				Before: map[string]any{"id": "subnet-managed"}, After: map[string]any{"id": "subnet-managed"},
			},
			"aws_db_subnet_group.g": {
				Address: "aws_db_subnet_group.g", ResourceType: "aws_db_subnet_group", Actions: []string{"create"},
				After: map[string]any{"subnet_ids": []any{"subnet-managed", "subnet-literal"}}, AfterUnknown: map[string]any{},
			},
		},
		Providers: map[string]string{"aws_db_subnet_group.g": DefaultProvider},
	}
	resolver := &fakeResolver{answers: map[string]Existence{"subnet-literal": Exists}}
	results, _ := Engine{Existence: []ExistenceRule{rule}, Resolver: resolver}.Evaluate(context.Background(), plan)
	if result := resultFor(t, results, "aws_db_subnet_group.g"); result.Verdict != VerdictSatisfied || resolver.calls != 1 {
		t.Fatalf("result = %+v, calls = %d; want only the literal looked up", result, resolver.calls)
	}
}

func resultFor(t *testing.T, results []Result, address string) Result {
	t.Helper()
	for _, result := range results {
		if result.Address == address {
			return result
		}
	}
	t.Fatalf("no result for %s in %+v", address, results)
	return Result{}
}

// prefetchSpy records what the engine asked for before evaluating.
type prefetchSpy struct {
	fakeResolver
	requests []LookupRequest
	rounds   int
}

func (p *prefetchSpy) Prefetch(_ context.Context, requests []LookupRequest) {
	p.rounds++
	p.requests = append(p.requests, requests...)
}

// Only identifiers the engine would actually send are gathered: a target the
// plan creates, an unknown value or another provider's scope is decided
// without AWS, so it must not appear in the prefetch either.
func TestPrefetchGathersOnlyWhatWouldBeSent(t *testing.T) {
	for _, tc := range []struct {
		name string
		plan Plan
		want []string
	}{
		{"external literal", subnetPlan(OriginLiteral, "vpc-1", nil), []string{"vpc-1"}},
		{"same-plan producer", subnetPlan(OriginSamePlan, nil, true, "aws_vpc.main"), nil},
		{"unknown identifier", subnetPlan(OriginLiteral, nil, true), nil},
		{"aliased provider", aliasedSubnetPlan(), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spy := &prefetchSpy{fakeResolver: fakeResolver{answers: map[string]Existence{"vpc-1": Exists}}}
			engine := Engine{Existence: []ExistenceRule{subnetRule()}, Resolver: spy}
			engine.Evaluate(context.Background(), tc.plan)
			var asked []string
			for _, request := range spy.requests {
				asked = append(asked, request.Identifier)
			}
			if strings.Join(asked, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("prefetched %v, want %v", asked, tc.want)
			}
			if spy.rounds != 1 {
				t.Fatalf("prefetch rounds = %d, want one gathering pass", spy.rounds)
			}
		})
	}
}

func aliasedSubnetPlan() Plan {
	plan := subnetPlan(OriginLiteral, "vpc-1", nil)
	plan.Providers["aws_subnet.s"] = "aws.west"
	return plan
}

// Answers arrive in whatever order AWS returns them; the report does not.
func TestEvaluationIsDeterministic(t *testing.T) {
	plan := subnetPlan(OriginLiteral, "vpc-1", nil)
	for address, change := range map[string]PlannedValues{
		"aws_subnet.b": {
			Address: "aws_subnet.b", ResourceType: "aws_subnet", Actions: []string{"create"},
			After: map[string]any{"vpc_id": "vpc-2"}, AfterUnknown: map[string]any{},
		},
		"aws_subnet.a": {
			Address: "aws_subnet.a", ResourceType: "aws_subnet", Actions: []string{"create"},
			After: map[string]any{"vpc_id": "vpc-3"}, AfterUnknown: map[string]any{},
		},
	} {
		plan.Changes[address] = change
		plan.References[address] = map[string]AttributeReference{"vpc_id": {Attribute: "vpc_id", Origin: OriginLiteral}}
		plan.Providers[address] = DefaultProvider
	}
	render := func() string {
		resolver := &unorderedResolver{answers: map[string]Existence{"vpc-1": Exists, "vpc-2": NotFound, "vpc-3": Unknown}}
		results, coverage := Engine{Existence: []ExistenceRule{subnetRule()}, Resolver: resolver}.Evaluate(context.Background(), plan)
		encoded, err := json.Marshal(struct {
			Results  []Result
			Coverage map[string]string
		}{results, coverage})
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	first := render()
	for range 5 {
		if got := render(); got != first {
			t.Fatalf("evaluation is not deterministic:\n%s\n%s", first, got)
		}
	}
}

// unorderedResolver answers concurrently and out of order.
type unorderedResolver struct {
	mu      sync.Mutex
	answers map[string]Existence
}

func (r *unorderedResolver) Exists(_ context.Context, _ Lookup, _ Scope, identifier string) (Existence, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.answers[identifier], "fake"
}

func (r *unorderedResolver) Prefetch(_ context.Context, requests []LookupRequest) {
	var group sync.WaitGroup
	for _, request := range requests {
		group.Add(1)
		go func() {
			defer group.Done()
			time.Sleep(time.Duration(len(request.Identifier)%3) * time.Millisecond)
			r.Exists(context.Background(), request.Lookup, request.Scope, request.Identifier)
		}()
	}
	group.Wait()
}
