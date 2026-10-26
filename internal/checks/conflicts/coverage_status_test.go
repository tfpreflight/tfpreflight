package conflicts

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/packs"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

// anyLookup answers every operation of one service with a fixed outcome.
type anyLookup struct {
	service string
	outcome Outcome
	err     error
}

func (a anyLookup) Service() string    { return a.service }
func (anyLookup) Supports(string) bool { return true }
func (a anyLookup) Lookup(context.Context, LookupRequest) (Outcome, error) {
	return a.outcome, a.err
}

func generatedConflictRules(t *testing.T) []Rule {
	t.Helper()
	data, err := packs.ReadFile("aws/conflict/generated-aws-" + testProviderVersion + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var file RuleFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	rules := make([]Rule, 0, len(file.Rules))
	for _, entry := range file.Rules {
		rules = append(rules, entry.Rule)
	}
	if len(rules) == 0 {
		t.Fatal("no generated conflict rules")
	}
	return rules
}

// Coverage for a type with a generated conflict rule reports what the resolver
// did, never not-applicable.
func TestGeneratedConflictTypesNeverReportNotApplicable(t *testing.T) {
	rules := generatedConflictRules(t)
	for _, scenario := range []struct {
		name     string
		registry *Registry
		known    bool
		want     model.CheckStatus
	}{
		{"identity available", registryAnswering(rules, OutcomeNotFound, nil), true, model.CheckChecked},
		{"identity taken", registryAnswering(rules, OutcomeExists, nil), true, model.CheckChecked},
		{"lookup failed", registryAnswering(rules, OutcomeUnknown, errors.New("AccessDenied")), true, model.CheckUnverifiable},
		{"identity unknown before apply", registryAnswering(rules, OutcomeNotFound, nil), false, model.CheckUnverifiable},
		{"AWS context unresolved", nil, true, model.CheckPartialAWSContext},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			resolver := NewResolver(rules, scenario.registry)
			for _, rule := range rules {
				_, coverage := resolver.Check(context.Background(), []model.PlannedChange{identityChange(rule, scenario.known)})
				assertConflictCoverage(t, rule, coverage, scenario.want)
			}
		})
	}
}

// registryAnswering registers one adapter per lookup service that answers
// every lookup with outcome and err.
func registryAnswering(rules []Rule, outcome Outcome, err error) *Registry {
	registry := NewRegistry()
	seen := map[string]bool{}
	for _, rule := range rules {
		if !seen[rule.LookupService] {
			seen[rule.LookupService] = true
			registry.Register(anyLookup{rule.LookupService, outcome, err})
		}
	}
	return registry
}

// identityChange is a planned create of the rule's resource type whose
// identity parts are known, or all unknown until apply.
func identityChange(rule Rule, known bool) model.PlannedChange {
	after, unknown := map[string]any{}, map[string]any{}
	for _, part := range rule.parts() {
		if known {
			after[part.Attribute] = "existing-identity"
		} else {
			unknown[part.Attribute] = true
		}
	}
	return model.PlannedChange{Address: rule.ResourceType + ".test", ResourceType: rule.ResourceType, ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate, After: after, AfterUnknown: unknown}
}

func assertConflictCoverage(t *testing.T, rule Rule, coverage []Coverage, want model.CheckStatus) {
	t.Helper()
	if len(coverage) != 1 {
		t.Fatalf("%s: coverage %+v", rule.ResourceType, coverage)
	}
	got := coverage[0].Status.CheckStatus()
	if got == model.CheckNotApplicable {
		t.Errorf("%s reports conflicts not-applicable (%s: %s)", rule.ResourceType, coverage[0].Status, coverage[0].Detail)
	} else if got != want {
		t.Errorf("%s reports %s, want %s (%s: %s)", rule.ResourceType, got, want, coverage[0].Status, coverage[0].Detail)
	}
}

// Every resolver status maps to a coverage status, and only a type the
// resolver has no rule for, or whose duplicate create is proven harmless, is
// not-applicable.
func TestResolverStatusesMapToCoverage(t *testing.T) {
	for status, want := range map[Status]model.CheckStatus{
		StatusChecked:              model.CheckChecked,
		StatusCompositeSupported:   model.CheckChecked,
		StatusLookupFailed:         model.CheckUnverifiable,
		StatusIdentityUnknown:      model.CheckUnverifiable,
		StatusCompositePartUnknown: model.CheckUnverifiable,
		StatusSemanticsNotProven:   model.CheckUnsupported,
		StatusAdapterMissing:       model.CheckUnsupported,
		StatusContextUnresolved:    model.CheckPartialAWSContext,
		StatusNoConflictPossible:   model.CheckNotApplicable,
		StatusNoRule:               model.CheckNotApplicable,
	} {
		if got := status.CheckStatus(); got != want {
			t.Errorf("%s -> %s, want %s", status, got, want)
		}
	}
}
