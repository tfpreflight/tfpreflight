package aws

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/checks/permissions"
	"github.com/tfpreflight/tfpreflight/internal/packs"

	packdata "github.com/tfpreflight/tfpreflight/packs"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

func TestBuildCoverageMarksSupportedAndUnsupportedResources(t *testing.T) {
	changes := []model.PlannedChange{
		{Address: "aws_s3_bucket.test", ResourceType: "aws_s3_bucket", ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate, After: map[string]any{"bucket": "test"}},
		{Address: "aws_vpc.test", ResourceType: "aws_vpc", ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate},
	}
	coverage := buildCoverage(changes, resolvedForTest(t, changes), model.AWSContext{ApplyIdentityKnown: true}, nil, false)
	if len(coverage.Resources) != 2 || coverage.Resources[0].Permissions != model.CheckChecked || coverage.Resources[0].Conflicts != model.CheckChecked || coverage.Resources[1].Permissions != model.CheckUnsupported {
		t.Fatalf("unexpected coverage: %#v", coverage)
	}
}

// A resource with a required API operation that maps to no IAM action has not
// been fully checked. Reporting it as "checked" would present a partial answer
// as a complete one, which is the most dangerous way to be wrong about
// permissions.
func TestUnresolvedRequiredOperationMakesCoveragePartial(t *testing.T) {
	change := model.PlannedChange{Address: "aws_thing.test", ResourceType: "aws_thing", ProviderName: "aws", Action: model.ActionCreate}
	rules := []packs.ResolvedRule{{Change: change, Action: packs.ActionRule{Operations: []packs.OperationRule{
		{Service: "thing", Name: "CreateThing", Permission: "thing:CreateThing", Certainty: "required"},
		{Service: "thing", Name: "PutThingPolicy", Certainty: "required"},
	}}}}
	coverage := buildCoverage([]model.PlannedChange{change}, rules, model.AWSContext{ApplyIdentityKnown: true}, nil, true)
	if len(coverage.Resources) != 1 {
		t.Fatalf("resources = %d", len(coverage.Resources))
	}
	if got := coverage.Resources[0].Permissions; got != model.CheckPartialUnresolvedAuthorization {
		t.Fatalf("permissions = %s, want %s", got, model.CheckPartialUnresolvedAuthorization)
	}
	if want := []string{"thing:PutThingPolicy"}; strings.Join(coverage.Resources[0].UnresolvedAuthorizationOperations, ",") != strings.Join(want, ",") {
		t.Fatalf("unresolved = %v, want %v", coverage.Resources[0].UnresolvedAuthorizationOperations, want)
	}
}

// When every required operation maps to an IAM action the result is complete.
func TestFullyMappedResourceStaysChecked(t *testing.T) {
	change := model.PlannedChange{Address: "aws_thing.test", ResourceType: "aws_thing", ProviderName: "aws", Action: model.ActionCreate}
	rules := []packs.ResolvedRule{{Change: change, Action: packs.ActionRule{Operations: []packs.OperationRule{
		{Service: "thing", Name: "CreateThing", Permission: "thing:CreateThing", Certainty: "required"},
	}}}}
	coverage := buildCoverage([]model.PlannedChange{change}, rules, model.AWSContext{ApplyIdentityKnown: true}, nil, true)
	if got := coverage.Resources[0].Permissions; got != model.CheckChecked {
		t.Fatalf("permissions = %s, want %s", got, model.CheckChecked)
	}
}

// An unresolved operation must also surface as a finding, so the resource can
// never produce a silently clean result.
func TestUnresolvedAuthorizationProducesAFinding(t *testing.T) {
	change := model.PlannedChange{Address: "aws_thing.test", ResourceType: "aws_thing", ProviderName: "aws", Action: model.ActionCreate}
	rules := []packs.ResolvedRule{{Change: change, Action: packs.ActionRule{Operations: []packs.OperationRule{
		{Service: "thing", Name: "PutThingPolicy", Certainty: "required"},
	}}}}
	findings := permissions.PredictUnresolvedAuthorization([]model.PlannedChange{change}, rules)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].ID != "aws.permission-coverage-incomplete" || findings[0].Resource != "aws_thing.test" {
		t.Fatalf("finding = %#v", findings[0])
	}
	if findings[0].Brief != "The permissions for these calls were not checked: thing:PutThingPolicy." || !strings.HasPrefix(findings[0].Next, "Check: ") {
		t.Fatalf("brief = %q, next = %q", findings[0].Brief, findings[0].Next)
	}
	if !strings.Contains(findings[0].Problem, "thing:PutThingPolicy") {
		t.Fatalf("problem does not name the operation: %q", findings[0].Problem)
	}
}

// A conditional operation whose condition the plan can decide, and does not
// satisfy, is legitimately skipped rather than a coverage gap.
func TestEvaluableConditionNotSatisfiedIsNotACoverageGap(t *testing.T) {
	change := model.PlannedChange{Address: "aws_thing.test", ResourceType: "aws_thing", ProviderName: "aws", Action: model.ActionCreate, After: map[string]any{}}
	rules := []packs.ResolvedRule{{Change: change, Action: packs.ActionRule{Operations: []packs.OperationRule{
		{Service: "thing", Name: "CreateThing", Permission: "thing:CreateThing", Certainty: "required"},
		{
			Service: "thing", Name: "TagThing", Permission: "thing:TagThing", Certainty: packs.CertaintyConditional,
			Condition: &packs.OperationCondition{Type: packs.ConditionAttributeSet, Field: "tags"},
		},
	}}}}
	if findings := permissions.PredictUnresolvedAuthorization([]model.PlannedChange{change}, rules); len(findings) != 0 {
		t.Fatalf("findings = %#v, want none", findings)
	}
	coverage := buildCoverage([]model.PlannedChange{change}, rules, model.AWSContext{ApplyIdentityKnown: true}, nil, true)
	if got := coverage.Resources[0].Permissions; got != model.CheckChecked {
		t.Fatalf("permissions = %s, want %s", got, model.CheckChecked)
	}
}

// conditionalRules builds a change whose only conditional operation has the
// given condition, alongside one ordinary required operation.
func conditionalRules(condition *packs.OperationCondition, after map[string]any) (model.PlannedChange, []packs.ResolvedRule) {
	change := model.PlannedChange{Address: "aws_thing.test", ResourceType: "aws_thing", ProviderName: "aws", Action: model.ActionCreate, After: after}
	rules := []packs.ResolvedRule{{Change: change, Action: packs.ActionRule{Operations: []packs.OperationRule{
		{Service: "thing", Name: "CreateThing", Permission: "thing:CreateThing", Certainty: "required"},
		{Service: "thing", Name: "RevokeThing", Permission: "thing:RevokeThing", Certainty: packs.CertaintyConditional, Condition: condition},
	}}}}
	return change, rules
}

// An operation the provider may call, whose code path the plan does not
// describe, must not vanish. It cannot be checked and it cannot be dismissed,
// so it has to show up as incomplete coverage.
func TestUnevaluableConditionMakesCoveragePartial(t *testing.T) {
	change, rules := conditionalRules(&packs.OperationCondition{Type: "control-flow"}, map[string]any{})
	coverage := buildCoverage([]model.PlannedChange{change}, rules, model.AWSContext{ApplyIdentityKnown: true}, nil, true)
	if got := coverage.Resources[0].Permissions; got != model.CheckPartialUnevaluableCondition {
		t.Fatalf("permissions = %s, want %s", got, model.CheckPartialUnevaluableCondition)
	}
	if want := []string{"thing:RevokeThing"}; strings.Join(coverage.Resources[0].UnevaluableConditionOperations, ",") != strings.Join(want, ",") {
		t.Fatalf("unevaluable = %v, want %v", coverage.Resources[0].UnevaluableConditionOperations, want)
	}
}

// A conditional operation with no condition at all is equally undecidable.
func TestConditionalOperationWithNoConditionIsUnevaluable(t *testing.T) {
	change, rules := conditionalRules(nil, map[string]any{})
	coverage := buildCoverage([]model.PlannedChange{change}, rules, model.AWSContext{ApplyIdentityKnown: true}, nil, true)
	if !coverage.Resources[0].Permissions.IsPartial() {
		t.Fatalf("permissions = %s, want a partial status", coverage.Resources[0].Permissions)
	}
}

// The gap must be visible as a finding, not only in the coverage summary.
func TestUnevaluableConditionProducesACoverageFinding(t *testing.T) {
	change, rules := conditionalRules(&packs.OperationCondition{Type: "control-flow"}, map[string]any{})
	findings := permissions.PredictUnresolvedAuthorization([]model.PlannedChange{change}, rules)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Problem, "thing:RevokeThing") {
		t.Fatalf("problem does not name the operation: %q", findings[0].Problem)
	}
}

// Not knowing whether a path runs is not the same as knowing it will fail, or
// even that it might: it is a coverage note, so --fail-on warning ignores it,
// and it claims no confidence it does not have.
func TestUnevaluableConditionIsOnlyACoverageNote(t *testing.T) {
	change, rules := conditionalRules(&packs.OperationCondition{Type: "control-flow"}, map[string]any{})
	findings := permissions.PredictUnresolvedAuthorization([]model.PlannedChange{change}, rules)
	if findings[0].Severity != model.SeverityInfo || findings[0].Confidence != model.ConfidenceLow {
		t.Fatalf("severity, confidence = %s, %s; want info, low", findings[0].Severity, findings[0].Confidence)
	}
	if len(findings[0].Gaps) != 1 || !strings.Contains(findings[0].Gaps[0].Summary, "thing:RevokeThing") {
		t.Fatalf("gaps = %+v, want one naming thing:RevokeThing", findings[0].Gaps)
	}
}

// An evaluable condition the plan satisfies is checked like any other
// requirement.
func TestEvaluableConditionSatisfiedIsChecked(t *testing.T) {
	operation := packs.OperationRule{
		Service: "thing", Name: "TagThing", Permission: "thing:TagThing", Certainty: packs.CertaintyConditional,
		Condition: &packs.OperationCondition{Type: packs.ConditionAttributeSet, Field: "tags"},
	}
	change := model.PlannedChange{After: map[string]any{"tags": map[string]any{"Name": "x"}}}
	if !operation.Required(change) {
		t.Fatal("a satisfied condition must make the permission required")
	}
	if !operation.ConditionEvaluable() {
		t.Fatal("an attribute condition must be evaluable")
	}
}

// A value terraform cannot know until apply is treated as set, so the
// permission is checked rather than quietly dropped.
func TestEvaluableConditionUnknownIsCheckedConservatively(t *testing.T) {
	operation := packs.OperationRule{
		Service: "thing", Name: "TagThing", Permission: "thing:TagThing", Certainty: packs.CertaintyConditional,
		Condition: &packs.OperationCondition{Type: packs.ConditionAttributeSet, Field: "tags"},
	}
	change := model.PlannedChange{After: map[string]any{}, AfterUnknown: map[string]any{"tags": true}}
	if !operation.Required(change) {
		t.Fatal("an unknown condition value must be checked rather than skipped")
	}
}

func TestUnsupportedProviderVersionIsReported(t *testing.T) {
	changes := []model.PlannedChange{{Address: "aws_vpc.test", ResourceType: "aws_vpc", ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate}}
	coverage := buildCoverage(changes, nil, model.AWSContext{}, nil, false)
	if coverage.ProviderKnowledge != model.CheckUnsupported {
		t.Fatalf("provider knowledge = %s, want %s", coverage.ProviderKnowledge, model.CheckUnsupported)
	}
	finding := unsupportedProviderFinding("6.65.0")
	if finding.Severity != model.SeverityWarning || finding.Confidence != model.ConfidenceHigh {
		t.Fatalf("finding = %#v", finding)
	}
	if !strings.Contains(finding.Problem, "6.65.0") {
		t.Fatalf("problem does not name the version: %q", finding.Problem)
	}
	if finding.Brief != "There are no rules for AWS provider version 6.65.0, so no AWS checks ran." || !strings.HasPrefix(finding.Next, "Fix: ") {
		t.Fatalf("brief = %q, next = %q", finding.Brief, finding.Next)
	}
}

// A version the project calls supported must be one the binary can actually
// load. The opposite - claiming support the runtime then denies - is the worst
// possible outcome, because the user is told the version works and then gets no
// checks.

// resolvedForTest resolves the shipped pack for a set of planned changes, the
// same way Run does before handing rules to the checks.
// resolvedForTest resolves against the hand-written default pack, the same
// pack these tests used before the runtime was split into packages.
func resolvedForTest(t *testing.T, changes []model.PlannedChange) []packs.ResolvedRule {
	t.Helper()
	data, err := packdata.AWS.ReadFile("aws/knowledge/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack packs.KnowledgePack
	if err := json.Unmarshal(data, &pack); err != nil {
		t.Fatal(err)
	}
	return packs.ResolveRules(pack, changes)
}
