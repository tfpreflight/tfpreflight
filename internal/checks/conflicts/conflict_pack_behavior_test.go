package conflicts

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/packs"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

// alwaysExists answers every lookup with "AWS already has this identity",
// which is the only outcome that can produce a conflict finding.
type alwaysExists struct{ service, operation string }

func (a alwaysExists) Service() string         { return a.service }
func (a alwaysExists) Supports(op string) bool { return op == a.operation }
func (a alwaysExists) Lookup(context.Context, LookupRequest) (Outcome, error) {
	return OutcomeExists, nil
}

// The runtime pack is generated, so what it ships is proven by behaviour: a
// generated rule still warns, and generation cannot turn it into a blocking one.
// Both checks use the real loader and resolver.
func TestShippedConflictRulesWarnWithoutBlocking(t *testing.T) {
	rules, err := loadConflictRules("6.64.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 {
		t.Fatal("no conflict rules load for 6.64.0")
	}
	checked, refused := 0, 0
	for _, rule := range rules {
		if rule.Identity.Composite() || rule.IdentityField == "" {
			continue
		}
		findings, coverage := checkTakenIdentity(rule)
		// A rule whose create is idempotent or unproven exists precisely so the
		// resolver refuses. An existing identity is not a failure there.
		if rule.CreateSemantics != SemanticsDuplicateError {
			assertConflictRefused(t, rule, findings, coverage)
			refused++
			continue
		}
		if len(findings) != 1 {
			t.Errorf("%s produced %d findings for an identity AWS already has (coverage %+v)",
				rule.ResourceType, len(findings), coverage)
			continue
		}
		checked++
		assertConflictSeverity(t, rule, findings[0])
	}
	if checked == 0 || refused == 0 {
		t.Fatalf("exercised %d warning rules and %d refusals; both paths must be covered", checked, refused)
	}
}

// checkTakenIdentity runs one rule against a planned create whose identity
// AWS already has.
func checkTakenIdentity(rule Rule) ([]model.Finding, []Coverage) {
	registry := NewRegistry()
	registry.Register(alwaysExists{service: rule.LookupService, operation: rule.LookupOperation})
	resolver := NewResolver([]Rule{rule}, registry)
	change := model.PlannedChange{
		Address: rule.ResourceType + ".example", ResourceType: rule.ResourceType,
		ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate,
		After: map[string]any{rule.IdentityField: "taken"},
	}
	return resolver.Check(context.Background(), []model.PlannedChange{change})
}

func assertConflictRefused(t *testing.T, rule Rule, findings []model.Finding, coverage []Coverage) {
	t.Helper()
	if len(findings) != 0 {
		t.Errorf("%s has create semantics %q but still reported a conflict", rule.ResourceType, rule.CreateSemantics)
	}
	want := StatusSemanticsNotProven
	if rule.CreateSemantics == SemanticsIdempotent || rule.CreateSemantics == SemanticsUpsert {
		want = StatusNoConflictPossible
	}
	if len(coverage) != 1 || coverage[0].Status != want {
		t.Errorf("%s coverage = %+v, want %s", rule.ResourceType, coverage, want)
	}
}

// assertConflictSeverity checks only verified rules block; every other
// rule warns at medium confidence.
func assertConflictSeverity(t *testing.T, rule Rule, finding model.Finding) {
	t.Helper()
	blocking := finding.Severity == model.SeverityError && finding.Confidence == model.ConfidenceHigh
	if rule.Trust == TrustVerified {
		if !blocking {
			t.Errorf("%s is verified but its finding is %s/%s", rule.ResourceType, finding.Severity, finding.Confidence)
		}
		return
	}
	if blocking {
		t.Errorf("%s has trust %q but produces a blocking finding", rule.ResourceType, rule.Trust)
	}
	if finding.Severity != model.SeverityWarning || finding.Confidence != model.ConfidenceMedium {
		t.Errorf("%s produced %s/%s, want warning/medium", rule.ResourceType, finding.Severity, finding.Confidence)
	}
}

// Generation accepts only one semantic for the generated half of the pack.
// Anything else there would mean the projection invented behaviour.
func TestGeneratedConflictPackCarriesOnlyProvenDuplicates(t *testing.T) {
	data, err := packs.ReadFile("aws/conflict/generated-aws-6.64.0.json")
	if err != nil {
		t.Fatal(err)
	}
	var file RuleFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Rules) == 0 {
		t.Fatal("the generated conflict pack is empty")
	}
	for _, entry := range file.Rules {
		if entry.CreateSemantics != SemanticsDuplicateError {
			t.Errorf("%s has generated semantics %q", entry.ResourceType, entry.CreateSemantics)
		}
		if entry.Trust != TrustGenerated {
			t.Errorf("%s has generated trust %q", entry.ResourceType, entry.Trust)
		}
	}
}

// A resource type with no rule is uncovered, not clean: a type the pack
// leaves out must degrade to "no rule" rather than to a silent pass.
func TestResourceTypeRemovedFromThePackIsUncovered(t *testing.T) {
	rules, err := loadConflictRules("6.64.0")
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		if rule.ResourceType == "aws_dynamodb_table" {
			t.Fatal("aws_dynamodb_table is back in the pack; its create error is a state precondition, not a duplicate identity")
		}
	}
	resolver := NewResolver(rules, NewRegistry())
	findings, coverage := resolver.Check(context.Background(), []model.PlannedChange{{
		Address: "aws_dynamodb_table.example", ResourceType: "aws_dynamodb_table",
		ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate,
		After: map[string]any{"name": "taken"},
	}})
	if len(findings) != 0 {
		t.Fatalf("a removed resource type produced %d findings", len(findings))
	}
	if len(coverage) != 1 || coverage[0].Status != StatusNoRule {
		t.Fatalf("coverage = %+v, want %s", coverage, StatusNoRule)
	}
}

// Conflict knowledge is version-exact for the same reason permissions are: a
// release can change which API a resource calls, and therefore what a duplicate
// identity means.
func TestConflictPackRejectsOtherProviderVersions(t *testing.T) {
	for _, version := range []string{"6.16.0", "6.70.0", "7.0.0", ""} {
		rules, err := loadConflictRules(version)
		if err != nil {
			t.Fatalf("%s: %v", version, err)
		}
		if len(rules) != 0 {
			t.Errorf("%d conflict rules loaded for unsupported version %q", len(rules), version)
		}
	}
	rules, err := loadConflictRules("6.64.0")
	if err != nil || len(rules) == 0 {
		t.Fatalf("6.64.0 loaded %d rules: %v", len(rules), err)
	}
	// The curated pack's recorded semantics must survive loading: two of its
	// entries exist precisely to keep resources out of the duplicate resolver.
	semantics := map[string]string{}
	for _, rule := range rules {
		semantics[rule.ResourceType] = rule.CreateSemantics
	}
	for resourceType, want := range map[string]string{
		"aws_ecr_repository":          SemanticsDuplicateError,
		"aws_cloudwatch_metric_alarm": SemanticsIdempotent,
		"aws_sesv2_contact_list":      SemanticsInconclusive,
	} {
		if semantics[resourceType] != want {
			t.Errorf("%s semantics = %q, want %q", resourceType, semantics[resourceType], want)
		}
	}
}

// IAM users and groups have verified duplicate-create evidence: a second create of an
// existing name fails with EntityAlreadyExists. Their curated rules are
// verified, win over the generated ones, and so block again.
func TestVerifiedIAMConflictRulesBlock(t *testing.T) {
	rules, err := loadConflictRules("6.64.0")
	if err != nil {
		t.Fatal(err)
	}
	byType := map[string]Rule{}
	for _, rule := range rules {
		byType[rule.ResourceType] = rule
	}
	for _, resourceType := range []string{"aws_iam_user", "aws_iam_group"} {
		rule, found := byType[resourceType]
		if !found || rule.Trust != TrustVerified {
			t.Fatalf("%s rule = %+v, want the verified curated rule", resourceType, rule)
		}
		registry := NewRegistry()
		registry.Register(alwaysExists{service: rule.LookupService, operation: rule.LookupOperation})
		change := model.PlannedChange{Address: resourceType + ".taken", ResourceType: resourceType, ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate, After: map[string]any{"name": "taken"}}
		findings, _ := NewResolver(rules, registry).Check(context.Background(), []model.PlannedChange{change})
		if len(findings) != 1 || findings[0].Severity != model.SeverityError || findings[0].Confidence != model.ConfidenceHigh {
			t.Fatalf("%s: findings = %+v, want one blocking conflict", resourceType, findings)
		}
	}
}

// PutDashboard overwrites a dashboard of the same name, though the model
// lists a ConflictException. The curated rule records that, wins over the
// generated duplicate rule, and so a dashboard is never reported as a
// conflict - on every version the packs cover - and never looked up.
func TestCloudWatchDashboardIsNeverAConflict(t *testing.T) {
	versions, err := packs.AWS()
	if err != nil || len(versions) == 0 {
		t.Fatalf("covered versions %v: %v", versions, err)
	}
	for _, version := range versions {
		rules, err := loadConflictRules(version)
		if err != nil {
			t.Fatal(err)
		}
		var dashboard *Rule
		for i := range rules {
			if rules[i].ResourceType == "aws_cloudwatch_dashboard" {
				dashboard = &rules[i]
			}
		}
		if dashboard == nil || dashboard.CreateSemantics != SemanticsUpsert {
			t.Fatalf("%s: dashboard rule = %+v, want the curated upsert rule", version, dashboard)
		}
		adapter := &fakeAdapter{service: "cloudwatch", operation: "GetDashboard", outcome: OutcomeExists}
		findings, coverage := resolverWith(*dashboard, adapter).Check(context.Background(),
			[]model.PlannedChange{createChange("aws_cloudwatch_dashboard", "aws_cloudwatch_dashboard.main", map[string]any{"dashboard_name": "main"}, nil)})
		if len(findings) != 0 || adapter.calls != 0 || coverage[0].Status != StatusNoConflictPossible {
			t.Fatalf("%s: findings %+v, lookups %d, coverage %+v", version, findings, adapter.calls, coverage)
		}
	}
}
