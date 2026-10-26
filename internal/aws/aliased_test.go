package aws

import (
	"context"
	"sort"
	"sync"
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/checks/conflicts"
	"github.com/tfpreflight/tfpreflight/internal/checks/permissions"
	"github.com/tfpreflight/tfpreflight/internal/checks/quotas"
	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/internal/plan"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// aliasedPlan is a two-provider plan as Terraform writes it: the default
// provider in eu-west-1 and aws.west, used directly by a root resource and
// passed to a module. A module that inherits the default provider, and a
// module with a provider block of its own, are there too.
const aliasedPlan = `{"format_version":"1.2",
"configuration":{
 "provider_config":{
  "aws":{"name":"aws","full_name":"registry.terraform.io/hashicorp/aws","expressions":{"region":{"constant_value":"eu-west-1"}}},
  "aws.west":{"name":"aws","full_name":"registry.terraform.io/hashicorp/aws","alias":"west","expressions":{"region":{"constant_value":"us-west-2"}}},
  "module.own:aws":{"name":"aws","full_name":"registry.terraform.io/hashicorp/aws","module_address":"module.own","expressions":{"region":{"constant_value":"ap-south-1"}}}},
 "root_module":{
  "resources":[
   {"address":"aws_s3_bucket.default","mode":"managed","type":"aws_s3_bucket","name":"default","provider_config_key":"aws","expressions":{"bucket":{"constant_value":"tfp-default"}}},
   {"address":"aws_s3_bucket.west","mode":"managed","type":"aws_s3_bucket","name":"west","provider_config_key":"aws.west","expressions":{"bucket":{"constant_value":"tfp-west"}}},
   {"address":"aws_iam_user.west","mode":"managed","type":"aws_iam_user","name":"west","provider_config_key":"aws.west","expressions":{"name":{"constant_value":"tfp-west"}}}],
  "module_calls":{
   "passes_west":{"source":"./modules/bucket","module":{"resources":[{"address":"aws_s3_bucket.this","mode":"managed","type":"aws_s3_bucket","name":"this","provider_config_key":"aws.west","expressions":{"bucket":{"references":["var.name"]}}}]}},
   "inherits":{"source":"./modules/bucket","module":{"resources":[{"address":"aws_s3_bucket.this","mode":"managed","type":"aws_s3_bucket","name":"this","provider_config_key":"aws","expressions":{"bucket":{"references":["var.name"]}}}]}},
   "own":{"source":"./modules/own","module":{"resources":[{"address":"aws_s3_bucket.this","mode":"managed","type":"aws_s3_bucket","name":"this","provider_config_key":"module.own:aws","expressions":{"bucket":{"constant_value":"tfp-own"}}}]}}}}},
"resource_changes":[
 {"address":"aws_s3_bucket.default","mode":"managed","type":"aws_s3_bucket","name":"default","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"after":{"bucket":"tfp-default"},"after_unknown":{}}},
 {"address":"aws_s3_bucket.west","mode":"managed","type":"aws_s3_bucket","name":"west","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"after":{"bucket":"tfp-west"},"after_unknown":{}}},
 {"address":"aws_iam_user.west","mode":"managed","type":"aws_iam_user","name":"west","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"after":{"name":"tfp-west"},"after_unknown":{}}},
 {"address":"module.passes_west[0].aws_s3_bucket.this","module_address":"module.passes_west[0]","mode":"managed","type":"aws_s3_bucket","name":"this","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"after":{"bucket":"tfp-passed-west"},"after_unknown":{}}},
 {"address":"module.inherits.aws_s3_bucket.this","module_address":"module.inherits","mode":"managed","type":"aws_s3_bucket","name":"this","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"after":{"bucket":"tfp-inherited"},"after_unknown":{}}},
 {"address":"module.own.aws_s3_bucket.this","module_address":"module.own","mode":"managed","type":"aws_s3_bucket","name":"this","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"after":{"bucket":"tfp-own"},"after_unknown":{}}}]}`

// onDefault are the changes on the default provider; every other AWS change
// is on another configuration.
var onDefault = map[string]bool{"aws_s3_bucket.default": true, "module.inherits.aws_s3_bucket.this": true}

// blockingChecks fail every resource they are given with a blocking finding,
// and record which resources those were.
type blockingChecks struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (b *blockingChecks) fail(address, category string) model.Finding {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seen[address] = true
	return model.Finding{ID: "test.blocking", Provider: "aws", Resource: address, Category: category, Severity: model.SeverityError, Confidence: model.ConfidenceHigh}
}

func (b *blockingChecks) fromRules(rules []packs.ResolvedRule, category string) []model.Finding {
	var findings []model.Finding
	for _, rule := range rules {
		findings = append(findings, b.fail(rule.Change.Address, category))
	}
	return findings
}

func (b *blockingChecks) fromChanges(changes []model.PlannedChange, category string) []model.Finding {
	var findings []model.Finding
	for _, change := range changes {
		findings = append(findings, b.fail(change.Address, category))
	}
	return findings
}

func (b *blockingChecks) checks() awsChecks {
	return awsChecks{
		Conflicts: func(_ context.Context, _ RunContext, rules []packs.ResolvedRule) ([]model.Finding, error) {
			return b.fromRules(rules, "resource-conflict"), nil
		},
		IdentityConflicts: func(_ context.Context, _ RunContext, _ string, changes []model.PlannedChange) ([]model.Finding, []conflicts.Coverage, error) {
			return b.fromChanges(changes, "resource-conflict"), nil, nil
		},
		EC2VCPU: func(_ context.Context, _ RunContext, rules []packs.ResolvedRule) ([]model.Finding, error) {
			return b.fromRules(rules, "quota"), nil
		},
		Quotas: func(_ context.Context, _ RunContext, changes []model.PlannedChange, _ map[string]quotas.Rule) []model.Finding {
			return b.fromChanges(changes, "quota")
		},
		Permissions: func(_ context.Context, _ RunContext, rules []packs.ResolvedRule) permissions.Result {
			return permissions.Result{Findings: b.fromRules(rules, "permissions")}
		},
		Dependencies: func(context.Context, RunContext, []byte, string) (dependencyOutcome, error) {
			return dependencyOutcome{}, nil
		},
	}
}

func TestParsePlanCarriesTheProviderConfiguration(t *testing.T) {
	changes, err := plan.ParsePlan([]byte(aliasedPlan))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"aws_s3_bucket.default":                    "aws",
		"aws_s3_bucket.west":                       "aws.west",
		"aws_iam_user.west":                        "aws.west",
		"module.passes_west[0].aws_s3_bucket.this": "aws.west",
		"module.inherits.aws_s3_bucket.this":       "aws",
		"module.own.aws_s3_bucket.this":            "module.own:aws",
	}
	for _, change := range changes {
		if change.ProviderConfigKey != want[change.Address] {
			t.Errorf("%s: provider configuration %q, want %q", change.Address, change.ProviderConfigKey, want[change.Address])
		}
		if change.OnDefaultAWSProvider() != onDefault[change.Address] {
			t.Errorf("%s: on the default provider = %v", change.Address, change.OnDefaultAWSProvider())
		}
	}
	if len(changes) != len(want) {
		t.Fatalf("parsed %d changes, want %d", len(changes), len(want))
	}
}

// A resource on an aliased provider, directly or through a module, or on a
// module's own provider, is never given to a check that calls AWS, never
// blocks, and is partial in every AWS check with the reason. Resources on the
// default provider are checked as before.
func TestAliasedProvidersArePartialAndNeverBlock(t *testing.T) {
	changes, err := plan.ParsePlan([]byte(aliasedPlan))
	if err != nil {
		t.Fatal(err)
	}
	// A change whose configuration the plan does not record is treated as
	// aliased too.
	unknown := model.PlannedChange{Address: "aws_s3_bucket.unknown", ResourceType: "aws_s3_bucket", ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate, After: map[string]any{"bucket": "tfp-unknown"}}
	changes = append(changes, unknown)

	inspector := "arn:aws:iam::" + contextTestAccount + ":user/inspector"
	run := resolveRunContext(context.Background(), contextSourcesFor(inspector), []byte(aliasedPlan), "arn:aws:iam::"+contextTestAccount+":role/apply")
	if !run.Inspects() || !run.Identity.ApplyIdentityKnown {
		t.Fatalf("context not resolved: %q / %q", run.Unresolved, run.InspectionUnavailable)
	}
	fake := &blockingChecks{seen: map[string]bool{}}
	result, err := runChecks(context.Background(), fake.checks(), run, changes, testProviderVersion, []byte(aliasedPlan))
	if err != nil {
		t.Fatal(err)
	}

	assertOnlyDefaultInspected(t, fake.seen)
	for _, finding := range result.Findings {
		if !onDefault[finding.Resource] && finding.Severity == model.SeverityError {
			t.Errorf("%s: blocking finding %s", finding.Resource, finding.ID)
		}
	}
	covered := 0
	for _, resource := range result.Coverage.Resources {
		if onDefault[resource.Resource] {
			if resource.UnresolvedAWSContext != "" {
				t.Errorf("%s: default provider resource marked %q", resource.Resource, resource.UnresolvedAWSContext)
			}
			continue
		}
		covered++
		assertAliasedPartial(t, resource)
	}
	if covered != 5 {
		t.Fatalf("coverage lists %d aliased resources, want 5", covered)
	}
}

// assertOnlyDefaultInspected fails unless the checks that call AWS saw every
// resource on the default provider and nothing else.
func assertOnlyDefaultInspected(t *testing.T, seen map[string]bool) {
	t.Helper()
	var addresses []string
	for address := range seen {
		addresses = append(addresses, address)
		if !onDefault[address] {
			t.Errorf("%s was given to a check that calls AWS", address)
		}
	}
	sort.Strings(addresses)
	if len(addresses) != len(onDefault) {
		t.Errorf("checks saw %v, want only the default provider's resources", addresses)
	}
}

// assertAliasedPartial fails unless every AWS check that applies to the
// resource is partial with the aliased-provider reason.
func assertAliasedPartial(t *testing.T, resource model.ResourceCoverage) {
	t.Helper()
	if resource.UnresolvedAWSContext != model.AliasedProviderReason {
		t.Errorf("%s: reason %q, want %q", resource.Resource, resource.UnresolvedAWSContext, model.AliasedProviderReason)
	}
	partial := 0
	for check, status := range map[string]model.CheckStatus{"permissions": resource.Permissions, "conflicts": resource.Conflicts, "quota": resource.Quota} {
		switch status {
		case model.CheckPartialAWSContext:
			partial++
		case model.CheckNotApplicable, model.CheckUnsupported, model.CheckNoQuotaRule:
			// Nothing to check here, whatever the provider configuration.
		default:
			t.Errorf("%s: %s = %s, want %s", resource.Resource, check, status, model.CheckPartialAWSContext)
		}
	}
	if partial == 0 {
		t.Errorf("%s: no check reported partial: %+v", resource.Resource, resource)
	}
}
