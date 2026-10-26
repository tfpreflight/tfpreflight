package dependencies

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// compiledRules loads the shipped rules for provider 6.64.0, so this test
// exercises generated knowledge rather than hand-built fixtures.
func compiledRules(t *testing.T) []ExistenceRule {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "compiled-rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Rules []ExistenceRule `json:"existence_rules"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Rules) == 0 {
		t.Fatal("no compiled rules")
	}
	return document.Rules
}

// The real plan contains one subnet whose VPC this plan creates and one whose
// VPC is an external literal. Only the second may be checked against AWS, and
// only its absence may be reported.
func TestCompiledRulesAgainstARealPlan(t *testing.T) {
	plan := probePlan(t)
	resolver := &fakeResolver{answers: map[string]Existence{"vpc-0123456789abcdef0": NotFound}}
	engine := Engine{Existence: compiledRules(t), Resolver: resolver}
	results, coverage := engine.Evaluate(context.Background(), plan)

	verdicts := map[string]string{}
	for _, result := range results {
		if result.Family == FamilyExistence {
			verdicts[result.Address] = result.Verdict
		}
	}
	if verdicts["aws_subnet.same_plan"] != VerdictSatisfiedByPlan {
		t.Fatalf("same-plan subnet verdict = %q, want %s", verdicts["aws_subnet.same_plan"], VerdictSatisfiedByPlan)
	}
	if verdicts["aws_subnet.external"] != VerdictViolation {
		t.Fatalf("external subnet verdict = %q, want %s", verdicts["aws_subnet.external"], VerdictViolation)
	}
	if resolver.calls != 1 {
		t.Fatalf("AWS was asked %d times, want exactly once for the external VPC", resolver.calls)
	}
	if coverage["aws_subnet.same_plan"] != CoverageChecked {
		t.Fatalf("same-plan coverage = %s", coverage["aws_subnet.same_plan"])
	}
	// The rule has no compiled existence rule; that is not a claim it has no
	// dependencies.
	if coverage["aws_security_group_rule.mixed"] != CoverageNoRule {
		t.Fatalf("security group rule coverage = %s, want %s", coverage["aws_security_group_rule.mixed"], CoverageNoRule)
	}
}

// When the external VPC exists, the same plan produces no finding at all.
func TestCompiledRulesAgainstARealPlanWhenEverythingExists(t *testing.T) {
	resolver := &fakeResolver{answers: map[string]Existence{"vpc-0123456789abcdef0": Exists}}
	results, _ := Engine{Existence: compiledRules(t), Resolver: resolver}.Evaluate(context.Background(), probePlan(t))
	for _, result := range results {
		if result.Finding != nil {
			t.Fatalf("unexpected finding %+v", result)
		}
	}
}

// A second real plan: a peering connection whose peer is in another region, a
// subnet under an aliased provider, and one module that inherits the default
// provider next to one that is passed the alias. Only the inherited module's
// subnet and the peering's local VPC may be checked against AWS.
func TestCompiledRulesRespectProviderConfigurationAndScope(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "scoped-references.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := ParsePlan(data)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &fakeResolver{answers: map[string]Existence{
		"vpc-0aaaaaaaaaaaaaaaa": NotFound,
		"vpc-0bbbbbbbbbbbbbbbb": NotFound,
		"vpc-0123456789abcdef0": NotFound,
		"vpc-0fedcba9876543210": NotFound,
	}}
	results, _ := Engine{Existence: compiledRules(t), Resolver: resolver}.Evaluate(context.Background(), plan)

	verdicts := map[string]string{}
	for _, result := range results {
		if result.Family == FamilyExistence && result.Verdict != VerdictNotApplicable {
			verdicts[result.Address+" "+strings.SplitN(result.Reason, " ", 2)[0]] = result.Verdict
		}
	}
	want := map[string]string{
		// peer_region is set: the peer VPC is looked for nowhere.
		"aws_vpc_peering_connection.cross peer_region": VerdictPartial,
		// The requester VPC is created by this plan.
		"aws_vpc_peering_connection.cross the": VerdictSatisfiedByPlan,
		// An aliased provider, directly or through a module.
		"aws_subnet.west aliased":                    VerdictPartial,
		"module.passes_west.aws_subnet.this aliased": VerdictPartial,
		"module.inherits.aws_subnet.this aws_vpc":    VerdictViolation,
	}
	for key, verdict := range want {
		if verdicts[key] != verdict {
			t.Errorf("%s: verdict = %q, want %q (all: %v)", key, verdicts[key], verdict, verdicts)
		}
	}
	if resolver.calls != 1 {
		t.Fatalf("AWS was asked %d times, want once: only the inherited module's subnet is in the default account and region", resolver.calls)
	}
}
