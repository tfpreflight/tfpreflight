package quotas

import (
	"context"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/rules"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// fakeInspector stands in for Service Quotas and CloudWatch so the runtime path
// can be exercised without consuming real quota headroom.
type fakeInspector struct {
	limit Measurement
	usage Measurement
}

func (f fakeInspector) Limit(context.Context, string, string) Measurement { return f.limit }
func (f fakeInspector) Usage(context.Context, *UsageMetric) Measurement {
	return f.usage
}

func (f fakeInspector) Counter(context.Context, *UsageCounter, UsageContext) Measurement {
	return f.usage
}

func vpcRule() map[string]Rule {
	return map[string]Rule{"aws_vpc": {
		Resource: "aws_vpc", ServiceCode: "vpc", QuotaCode: "L-F678F1CE", QuotaName: "VPCs per Region",
		Scope: rules.ScopeRegion, Adjustable: true,
		Consumption: rules.Consumption{Type: rules.ConsumptionResourceCount, Units: 1},
		Usage:       &UsageMetric{Namespace: "AWS/Usage", MetricName: "ResourceCount", Statistic: "Maximum"},
		Trust:       rules.TrustVerified, MappingEvidence: "test", UsageEvidence: "test", ScopeEvidence: "test",
	}}
}

func vpcChanges(count int) []model.PlannedChange {
	changes := make([]model.PlannedChange, 0, count)
	for index := 0; index < count; index++ {
		changes = append(changes, model.PlannedChange{
			Address: "aws_vpc.test", ResourceType: "aws_vpc",
			ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate,
		})
	}
	return changes
}

// The generated rule must actually reach the runtime: knowledge that only
// exists in an offline report checks nothing.
const testProviderVersion = "6.64.0"

func TestGeneratedQuotaRulesLoadForTheExactVersion(t *testing.T) {
	rules, loaded, err := LoadQuotaRules(testProviderVersion)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded {
		t.Fatalf("no quota rules ship for %s", testProviderVersion)
	}
	if _, found := rules["aws_vpc"]; !found {
		t.Fatalf("aws_vpc rule missing; loaded %d rules", len(rules))
	}
}

func TestGeneratedCounterRuleUsesCounterUsageAtRuntime(t *testing.T) {
	rules := map[string]Rule{"aws_customer_gateway": {
		Resource: "aws_customer_gateway", ServiceCode: "ec2", QuotaCode: "L-test", QuotaName: "Customer gateways per region",
		Consumption: rules.Consumption{Type: rules.ConsumptionResourceCount, Units: 1},
		Counter:     &UsageCounter{Adapter: "ec2:DescribeCustomerGateways", Operation: "DescribeCustomerGateways", Collection: "CustomerGateways", Pagination: "none"},
		Trust:       rules.TrustVerified, MappingEvidence: "test", UsageEvidence: "test", ScopeEvidence: "test",
	}}
	changes := []model.PlannedChange{{Address: "aws_customer_gateway.test", ResourceType: "aws_customer_gateway", ProviderName: "aws", Action: model.ActionCreate}}
	findings := PredictQuotas(context.Background(), changes, rules, fakeInspector{limit: Known(2), usage: Known(2)}, nil)
	if len(findings) != 1 || findings[0].Severity != model.SeverityError {
		t.Fatalf("generated counter rule did not produce the expected over-limit finding: %#v", findings)
	}
}

func TestInferredQuotaRuleNeverBlocksApply(t *testing.T) {
	rules := map[string]Rule{"aws_customer_gateway": {
		Resource: "aws_customer_gateway", ServiceCode: "ec2", QuotaCode: "L-test", QuotaName: "Customer gateways per region",
		Consumption: rules.Consumption{Type: rules.ConsumptionResourceCount, Units: 1}, Counter: &UsageCounter{Adapter: "test"}, Trust: "inferred",
	}}
	changes := []model.PlannedChange{{Address: "aws_customer_gateway.test", ResourceType: "aws_customer_gateway", ProviderName: "aws", Action: model.ActionCreate}}
	findings := PredictQuotas(context.Background(), changes, rules, fakeInspector{limit: Known(1), usage: Known(1)}, nil)
	if len(findings) != 1 || findings[0].Severity == model.SeverityError || findings[0].ID != "aws.quota-unverified" {
		t.Fatalf("inferred quota rule must be partial, got %#v", findings)
	}
	if findings[0].Severity != model.SeverityInfo || findings[0].Confidence != model.ConfidenceLow {
		t.Fatalf("partial semantic finding = %s, %s; want info, low", findings[0].Severity, findings[0].Confidence)
	}
}

// Quota knowledge is version-exact for the same reason permissions are: a
// release can change which service a resource calls and therefore which quota
// it consumes.
func TestQuotaRulesDoNotFallBackAcrossVersions(t *testing.T) {
	newer, err := packs.NewerThanCovered()
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"6.16.0", newer, ""} {
		rules, loaded, err := LoadQuotaRules(version)
		if err != nil {
			t.Fatalf("%s: %v", version, err)
		}
		if loaded || len(rules) != 0 {
			t.Fatalf("%s: quota rules must not be borrowed from another version", version)
		}
	}
}

// A plan that fits produces no finding at all.
func TestQuotaWithinLimitProducesNoFinding(t *testing.T) {
	inspector := fakeInspector{limit: Known(5), usage: Known(2)}
	findings := PredictQuotas(context.Background(), vpcChanges(1), vpcRule(), inspector, nil)
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want none", findings)
	}
}

// A plan that crosses the limit blocks, and the message states the arithmetic.
func TestQuotaExceededProducesABlockingFinding(t *testing.T) {
	inspector := fakeInspector{limit: Known(5), usage: Known(4)}
	findings := PredictQuotas(context.Background(), vpcChanges(2), vpcRule(), inspector, nil)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	finding := findings[0]
	if finding.Severity != model.SeverityError || finding.Confidence != model.ConfidenceHigh {
		t.Fatalf("finding = %+v, want a blocking high-confidence finding", finding)
	}
	if !strings.Contains(finding.Problem, "6") {
		t.Fatalf("problem should state the expected peak of 6: %q", finding.Problem)
	}
}

// Unknown usage must never block and must never pass silently: it is partial.
func TestUnknownUsageProducesAPartialFindingNotABlock(t *testing.T) {
	inspector := fakeInspector{limit: Known(5), usage: Unknown("CloudWatch returned no usage datapoints")}
	findings := PredictQuotas(context.Background(), vpcChanges(1), vpcRule(), inspector, nil)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1 partial finding", len(findings))
	}
	if findings[0].Severity == model.SeverityError {
		t.Fatal("unknown usage must not block an apply")
	}
	if findings[0].ID != "aws.quota-unverified" {
		t.Fatalf("id = %s", findings[0].ID)
	}
}

// An unreadable limit is equally partial: an unknown quota is not an unlimited
// one.
func TestUnknownLimitProducesAPartialFinding(t *testing.T) {
	inspector := fakeInspector{limit: Unknown("AccessDenied calling Service Quotas"), usage: Known(0)}
	findings := PredictQuotas(context.Background(), vpcChanges(1), vpcRule(), inspector, nil)
	if len(findings) != 1 || findings[0].Severity == model.SeverityError {
		t.Fatalf("findings = %#v, want one non-blocking finding", findings)
	}
	if !strings.Contains(findings[0].Problem, "AccessDenied") {
		t.Fatalf("problem should carry the cause: %q", findings[0].Problem)
	}
}

// A resource type with no known quota had nothing to check. It is reported as
// "no quota rule", not "not applicable", which would claim no quota exists.
func TestUnmappedResourceHasNoQuotaRule(t *testing.T) {
	changes := []model.PlannedChange{{
		Address: "aws_athena_workgroup.test", ResourceType: "aws_athena_workgroup",
		ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate,
	}}
	coverage := model.Coverage{Resources: []model.ResourceCoverage{{Resource: "aws_athena_workgroup.test"}}}
	ApplyQuotaCoverage(&coverage, changes, vpcRule(), true, nil)
	if coverage.Resources[0].Quota != model.CheckNoQuotaRule {
		t.Fatalf("quota coverage = %s, want %s", coverage.Resources[0].Quota, model.CheckNoQuotaRule)
	}
}

// A resource with a mapped quota is reported as checked.
func TestMappedResourceIsReportedChecked(t *testing.T) {
	coverage := model.Coverage{Resources: []model.ResourceCoverage{{Resource: "aws_vpc.test"}}}
	ApplyQuotaCoverage(&coverage, vpcChanges(1), vpcRule(), true, nil)
	if coverage.Resources[0].Quota != model.CheckChecked {
		t.Fatalf("quota coverage = %s, want %s", coverage.Resources[0].Quota, model.CheckChecked)
	}
}

// When a partial finding was produced, coverage must say partial rather than
// checked.
func TestPartialFindingDowngradesCoverage(t *testing.T) {
	coverage := model.Coverage{Resources: []model.ResourceCoverage{{Resource: "aws_vpc.test"}}}
	findings := []model.Finding{{ID: "aws.quota-unverified", Resource: "aws_vpc.test"}}
	ApplyQuotaCoverage(&coverage, vpcChanges(1), vpcRule(), true, findings)
	if coverage.Resources[0].Quota.IsPartial() != true {
		t.Fatalf("quota coverage = %s, want a partial state", coverage.Resources[0].Quota)
	}
}

// A quota is decided once per resource type and reported on the type's first
// resource; an unverified quota leaves every resource of the type partial, not
// only that one.
func TestUnverifiedQuotaCoversEveryResourceOfTheType(t *testing.T) {
	changes := vpcChanges(2)
	changes[1].Address = "aws_vpc.second"
	coverage := model.Coverage{}
	for _, change := range changes {
		coverage.Resources = append(coverage.Resources, model.ResourceCoverage{Resource: change.Address})
	}
	findings := []model.Finding{{ID: "aws.quota-unverified", Resource: changes[0].Address}}
	ApplyQuotaCoverage(&coverage, changes, vpcRule(), true, findings)
	for _, resource := range coverage.Resources {
		if !resource.Quota.IsPartial() {
			t.Errorf("%s quota = %s, want partial", resource.Resource, resource.Quota)
		}
	}
}

// A destroy-only plan consumes nothing, so no quota question arises.
func TestDestroyOnlyPlanRaisesNoQuotaFinding(t *testing.T) {
	changes := []model.PlannedChange{{
		Address: "aws_vpc.test", ResourceType: "aws_vpc",
		ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionDelete,
	}}
	inspector := fakeInspector{limit: Known(5), usage: Known(5)}
	if findings := PredictQuotas(context.Background(), changes, vpcRule(), inspector, nil); len(findings) != 0 {
		t.Fatalf("findings = %#v, want none", findings)
	}
}

// The quota runtime pack is generated. The population is pinned, and every
// shipped rule is too weakly evidenced to block, so an exceeded quota from this
// pack is a warning.
func TestShippedQuotaPackPopulationAndBlockingAreFrozen(t *testing.T) {
	rules, loaded, err := LoadQuotaRules(testProviderVersion)
	if err != nil || !loaded {
		t.Fatalf("load quota rules: loaded=%v err=%v", loaded, err)
	}
	if len(rules) != 7 {
		t.Fatalf("shipped quota rules = %d, want 7; regeneration changed coverage, which this remediation must not do", len(rules))
	}
	for resourceType, rule := range rules {
		changes := []model.PlannedChange{{
			Address: resourceType + ".test", ResourceType: resourceType,
			ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate,
		}}
		// A limit of one already fully used is the strongest possible case for
		// blocking. It must still only warn.
		findings := PredictQuotas(context.Background(), changes, map[string]Rule{resourceType: rule},
			fakeInspector{limit: Known(1), usage: Known(1)}, nil)
		for _, finding := range findings {
			if finding.Severity == model.SeverityError && finding.Confidence == model.ConfidenceHigh {
				t.Errorf("%s produced a blocking quota finding from the shipped pack", resourceType)
			}
		}
	}
}
