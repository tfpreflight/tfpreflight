package conflicts

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

// fakeAdapter stands in for a typed AWS service lookup.
type fakeAdapter struct {
	service, operation string
	outcome            Outcome
	err                error
	calls              int
	capture            *LookupRequest
}

func (f *fakeAdapter) Service() string         { return f.service }
func (f *fakeAdapter) Supports(op string) bool { return op == f.operation }
func (f *fakeAdapter) Lookup(_ context.Context, request LookupRequest) (Outcome, error) {
	f.calls++
	if f.capture != nil {
		*f.capture = request
	}
	return f.outcome, f.err
}

func ecrRule() Rule {
	return Rule{ProviderVersion: "6.64.0", ResourceType: "aws_ecr_repository", IdentityField: "name", LookupService: "ecr", LookupOperation: "DescribeRepositories", CreateSemantics: SemanticsDuplicateError, Scope: "account_region", Trust: TrustGenerated}
}

func createChange(resourceType, address string, after map[string]any, unknown map[string]any) model.PlannedChange {
	return model.PlannedChange{Address: address, ResourceType: resourceType, ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate, After: after, AfterUnknown: unknown}
}

func resolverWith(rule Rule, adapter *fakeAdapter) *Resolver {
	registry := NewRegistry()
	if adapter != nil {
		registry.Register(adapter)
	}
	return NewResolver([]Rule{rule}, registry)
}

func TestExistingIdentityProducesConflict(t *testing.T) {
	adapter := &fakeAdapter{service: "ecr", operation: "DescribeRepositories", outcome: OutcomeExists}
	findings, coverage := resolverWith(ecrRule(), adapter).Check(context.Background(),
		[]model.PlannedChange{createChange("aws_ecr_repository", "aws_ecr_repository.example", map[string]any{"name": "app"}, nil)})
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if findings[0].Category != "resource-conflict" || findings[0].ID != "aws.identity-conflict" {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
	if coverage[0].Status != StatusChecked {
		t.Fatalf("coverage = %+v", coverage[0])
	}
}

func TestAbsentIdentityProducesNoConflict(t *testing.T) {
	adapter := &fakeAdapter{service: "ecr", operation: "DescribeRepositories", outcome: OutcomeNotFound}
	findings, coverage := resolverWith(ecrRule(), adapter).Check(context.Background(),
		[]model.PlannedChange{createChange("aws_ecr_repository", "aws_ecr_repository.example", map[string]any{"name": "app"}, nil)})
	if len(findings) != 0 {
		t.Fatalf("absent identity produced %d findings", len(findings))
	}
	if coverage[0].Status != StatusChecked {
		t.Fatalf("coverage = %+v", coverage[0])
	}
}

func TestLookupErrorIsNeverTreatedAsAbsence(t *testing.T) {
	// A denied or throttled lookup says nothing about whether the object is
	// there, so it must not silently pass as "available".
	for _, err := range []error{errors.New("AccessDenied"), errors.New("throttling"), errors.New("dial tcp: i/o timeout")} {
		adapter := &fakeAdapter{service: "ecr", operation: "DescribeRepositories", outcome: OutcomeUnknown, err: err}
		findings, coverage := resolverWith(ecrRule(), adapter).Check(context.Background(),
			[]model.PlannedChange{createChange("aws_ecr_repository", "aws_ecr_repository.example", map[string]any{"name": "app"}, nil)})
		if coverage[0].Status != StatusLookupFailed {
			t.Fatalf("status = %s, want %s", coverage[0].Status, StatusLookupFailed)
		}
		if len(findings) != 1 || findings[0].ID != "aws.identity-conflict-unavailable" {
			t.Fatalf("expected an informational unavailable finding, got %+v", findings)
		}
		if findings[0].Severity == model.SeverityError {
			t.Fatal("an unanswered lookup must not block")
		}
	}
}

func TestIdempotentSemanticsNeverReachTheAdapter(t *testing.T) {
	// The CloudWatch control: an existing alarm is not a create conflict.
	rule := Rule{ProviderVersion: "6.64.0", ResourceType: "aws_cloudwatch_metric_alarm", IdentityField: "alarm_name", LookupService: "cloudwatch", LookupOperation: "DescribeAlarms", CreateSemantics: SemanticsIdempotent, Trust: TrustGenerated}
	adapter := &fakeAdapter{service: "cloudwatch", operation: "DescribeAlarms", outcome: OutcomeExists}
	findings, coverage := resolverWith(rule, adapter).Check(context.Background(),
		[]model.PlannedChange{createChange("aws_cloudwatch_metric_alarm", "aws_cloudwatch_metric_alarm.cpu", map[string]any{"alarm_name": "cpu"}, nil)})
	if len(findings) != 0 {
		t.Fatalf("idempotent create produced a conflict finding: %+v", findings)
	}
	if adapter.calls != 0 {
		t.Fatal("an idempotent rule must not perform a lookup")
	}
	if coverage[0].Status != StatusNoConflictPossible {
		t.Fatalf("coverage = %+v", coverage[0])
	}
}

func TestInconclusiveSemanticsAreNotChecked(t *testing.T) {
	rule := Rule{ProviderVersion: "6.64.0", ResourceType: "aws_sesv2_contact_list", IdentityField: "contact_list_name", LookupService: "sesv2", LookupOperation: "GetContactList", CreateSemantics: SemanticsInconclusive, Trust: TrustGenerated}
	adapter := &fakeAdapter{service: "sesv2", operation: "GetContactList", outcome: OutcomeExists}
	findings, coverage := resolverWith(rule, adapter).Check(context.Background(),
		[]model.PlannedChange{createChange("aws_sesv2_contact_list", "aws_sesv2_contact_list.l", map[string]any{"contact_list_name": "l"}, nil)})
	if len(findings) != 0 || adapter.calls != 0 {
		t.Fatal("inconclusive semantics must not produce a conflict")
	}
	if coverage[0].Status != StatusSemanticsNotProven {
		t.Fatalf("coverage = %+v", coverage[0])
	}
}

func TestUnknownIdentityIsSkippedNotGuessed(t *testing.T) {
	adapter := &fakeAdapter{service: "ecr", operation: "DescribeRepositories", outcome: OutcomeExists}
	resolver := resolverWith(ecrRule(), adapter)
	for _, change := range []model.PlannedChange{
		createChange("aws_ecr_repository", "a", map[string]any{"name": "x"}, map[string]any{"name": true}),
		createChange("aws_ecr_repository", "b", map[string]any{}, nil),
		createChange("aws_ecr_repository", "c", map[string]any{"name": ""}, nil),
	} {
		findings, coverage := resolver.Check(context.Background(), []model.PlannedChange{change})
		if len(findings) != 0 {
			t.Fatalf("%s produced a finding from an unknown identity", change.Address)
		}
		if coverage[0].Status != StatusIdentityUnknown {
			t.Fatalf("%s status = %s", change.Address, coverage[0].Status)
		}
	}
	if adapter.calls != 0 {
		t.Fatal("an unknown identity must not be looked up")
	}
}

func TestMissingAdapterIsDistinctFromNoRule(t *testing.T) {
	findings, coverage := resolverWith(ecrRule(), nil).Check(context.Background(),
		[]model.PlannedChange{createChange("aws_ecr_repository", "a", map[string]any{"name": "x"}, nil)})
	if len(findings) != 0 || coverage[0].Status != StatusAdapterMissing {
		t.Fatalf("expected adapter_missing, got %+v / %+v", findings, coverage)
	}
	_, coverage = resolverWith(ecrRule(), nil).Check(context.Background(),
		[]model.PlannedChange{createChange("aws_other_thing", "b", map[string]any{"name": "x"}, nil)})
	if coverage[0].Status != StatusNoRule {
		t.Fatalf("expected no_rule, got %+v", coverage[0])
	}
}

func TestTrustDrivesSeverityAndConfidence(t *testing.T) {
	adapter := &fakeAdapter{service: "ecr", operation: "DescribeRepositories", outcome: OutcomeExists}
	generated, _ := resolverWith(ecrRule(), adapter).Check(context.Background(),
		[]model.PlannedChange{createChange("aws_ecr_repository", "a", map[string]any{"name": "x"}, nil)})
	if generated[0].Severity != model.SeverityWarning || generated[0].Confidence != model.ConfidenceMedium {
		t.Fatalf("generated rule should warn: %+v", generated[0])
	}
	rule := ecrRule()
	rule.Trust = TrustVerified
	verified, _ := resolverWith(rule, adapter).Check(context.Background(),
		[]model.PlannedChange{createChange("aws_ecr_repository", "a", map[string]any{"name": "x"}, nil)})
	if verified[0].Severity != model.SeverityError || verified[0].Confidence != model.ConfidenceHigh {
		t.Fatalf("verified rule should block: %+v", verified[0])
	}
}

func TestNonCreateActionsAreIgnored(t *testing.T) {
	adapter := &fakeAdapter{service: "ecr", operation: "DescribeRepositories", outcome: OutcomeExists}
	change := createChange("aws_ecr_repository", "a", map[string]any{"name": "x"}, nil)
	change.Action = model.ActionUpdate
	findings, coverage := resolverWith(ecrRule(), adapter).Check(context.Background(), []model.PlannedChange{change})
	if len(findings) != 0 || len(coverage) != 0 || adapter.calls != 0 {
		t.Fatal("only creates can conflict on identity")
	}
}

func TestRegistryDispatchesByServiceAndOperation(t *testing.T) {
	registry := NewRegistry()
	registry.Register(&fakeAdapter{service: "ecr", operation: "DescribeRepositories"}, &fakeAdapter{service: "sesv2", operation: "GetConfigurationSet"})
	if _, ok := registry.For("ecr", "DescribeRepositories"); !ok {
		t.Fatal("ecr adapter not found")
	}
	if _, ok := registry.For("ecr", "SomethingElse"); ok {
		t.Fatal("adapter claimed an operation it does not support")
	}
	if _, ok := registry.For("unregistered", "Op"); ok {
		t.Fatal("unregistered service resolved")
	}
	if len(registry.Services()) != 2 {
		t.Fatalf("services = %v", registry.Services())
	}
}

func compositeRule() Rule {
	return Rule{
		ProviderVersion: "6.64.0", ResourceType: "aws_appmesh_virtual_node", IdentityField: "mesh_name",
		LookupService: "appmesh", LookupOperation: "DescribeVirtualNode", CreateSemantics: SemanticsDuplicateError, Trust: TrustGenerated,
		Identity: Identity{Type: "composite", Parts: []IdentityPart{{Attribute: "mesh_name", LookupField: "MeshName"}, {Attribute: "name", LookupField: "VirtualNodeName"}}},
	}
}

func TestCompositeIdentityPassesEveryPartToTheAdapter(t *testing.T) {
	adapter := &fakeAdapter{service: "appmesh", operation: "DescribeVirtualNode", outcome: OutcomeExists}
	var seen LookupRequest
	adapter.capture = &seen
	findings, coverage := resolverWith(compositeRule(), adapter).Check(context.Background(),
		[]model.PlannedChange{createChange("aws_appmesh_virtual_node", "aws_appmesh_virtual_node.test", map[string]any{"mesh_name": "m1", "name": "n1"}, nil)})
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if seen.Values["MeshName"] != "m1" || seen.Values["VirtualNodeName"] != "n1" {
		t.Fatalf("adapter received %+v", seen.Values)
	}
	if coverage[0].Status != StatusCompositeSupported {
		t.Fatalf("coverage = %+v", coverage[0])
	}
	// Every part must be visible in the finding, not flattened into a blob.
	notes := strings.Join(findings[0].Notes, "|")
	if !strings.Contains(notes, "mesh_name = m1") || !strings.Contains(notes, "name = n1") {
		t.Fatalf("identity not rendered per part: %v", findings[0].Notes)
	}
}

func TestCompositeIdentityWithAnUnknownPartIsSkipped(t *testing.T) {
	// One unknown part means the lookup would query a different object.
	adapter := &fakeAdapter{service: "appmesh", operation: "DescribeVirtualNode", outcome: OutcomeExists}
	findings, coverage := resolverWith(compositeRule(), adapter).Check(context.Background(),
		[]model.PlannedChange{createChange("aws_appmesh_virtual_node", "a", map[string]any{"mesh_name": "m1"}, map[string]any{"name": true})})
	if len(findings) != 0 {
		t.Fatalf("an unknown part produced a finding: %+v", findings)
	}
	if adapter.calls != 0 {
		t.Fatal("a lookup ran with an incomplete identity")
	}
	if coverage[0].Status != StatusCompositePartUnknown {
		t.Fatalf("coverage = %+v", coverage[0])
	}
}

func TestCompositeAbsentIdentityProducesNoFinding(t *testing.T) {
	adapter := &fakeAdapter{service: "appmesh", operation: "DescribeVirtualNode", outcome: OutcomeNotFound}
	findings, _ := resolverWith(compositeRule(), adapter).Check(context.Background(),
		[]model.PlannedChange{createChange("aws_appmesh_virtual_node", "a", map[string]any{"mesh_name": "m1", "name": "n1"}, nil)})
	if len(findings) != 0 {
		t.Fatalf("absent composite identity produced %+v", findings)
	}
}

func TestSingleFieldRulesStillWork(t *testing.T) {
	// Composite support must not change single-field behaviour.
	adapter := &fakeAdapter{service: "ecr", operation: "DescribeRepositories", outcome: OutcomeExists}
	var seen LookupRequest
	adapter.capture = &seen
	findings, coverage := resolverWith(ecrRule(), adapter).Check(context.Background(),
		[]model.PlannedChange{createChange("aws_ecr_repository", "a", map[string]any{"name": "app"}, nil)})
	if len(findings) != 1 || seen.Identity != "app" {
		t.Fatalf("single-field rule broke: findings=%d identity=%q", len(findings), seen.Identity)
	}
	if coverage[0].Status != StatusChecked {
		t.Fatalf("coverage = %+v", coverage[0])
	}
}
