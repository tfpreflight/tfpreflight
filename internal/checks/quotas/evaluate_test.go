package quotas

import (
	"errors"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/rules"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// The whole point of the check: a plan that would cross the limit is called
// out.
func TestPlanCrossingTheLimitExceeds(t *testing.T) {
	decision := Evaluate(Known(16), Known(12), Known(8))
	if decision.Verdict != VerdictExceeds || !decision.Blocking() {
		t.Fatalf("decision = %+v", decision)
	}
	if decision.Expected != 20 {
		t.Fatalf("expected total = %g, want 20", decision.Expected)
	}
}

// Exactly reaching the limit is allowed; quotas are a ceiling, not a strict
// inequality.
func TestUsageExactlyAtTheLimitIsWithin(t *testing.T) {
	if decision := Evaluate(Known(16), Known(8), Known(8)); decision.Verdict != VerdictWithin {
		t.Fatalf("verdict = %s, want %s", decision.Verdict, VerdictWithin)
	}
}

// The failure mode this package exists to prevent: an unknown component must
// never read as headroom. Each one is checked separately so a future change
// cannot quietly drop one of the guards.
func TestAnyUnknownComponentMakesTheVerdictUnknown(t *testing.T) {
	cases := map[string]Decision{
		"limit unknown":   Evaluate(Unknown("AccessDenied calling Service Quotas"), Known(0), Known(8)),
		"usage unknown":   Evaluate(Known(16), Unknown("CloudWatch returned no datapoints"), Known(8)),
		"planned unknown": Evaluate(Known(16), Known(0), Unknown("instance_type is not known until apply")),
	}
	for name, decision := range cases {
		if decision.Verdict != VerdictUnknown {
			t.Errorf("%s: verdict = %s, want %s", name, decision.Verdict, VerdictUnknown)
		}
		if decision.Blocking() {
			t.Errorf("%s: an unknown component must not produce a blocking finding", name)
		}
		if !decision.Partial() {
			t.Errorf("%s: an unknown verdict must be reported as partial coverage", name)
		}
		if decision.Reason == "" {
			t.Errorf("%s: an unknown verdict must say which component was missing", name)
		}
	}
}

// An unknown limit must not be treated as unlimited, even when usage and plan
// are both tiny.
func TestUnknownLimitIsNotTreatedAsUnlimited(t *testing.T) {
	decision := Evaluate(Unknown("quota code not published for this service"), Known(1), Known(1))
	if decision.Verdict != VerdictUnknown {
		t.Fatalf("verdict = %s", decision.Verdict)
	}
	if !strings.Contains(decision.Reason, "limit") {
		t.Fatalf("reason should name the limit: %q", decision.Reason)
	}
}

// An unknown usage figure must not be treated as zero, which would report a
// full account as empty.
func TestUnknownUsageIsNotTreatedAsZero(t *testing.T) {
	decision := Evaluate(Known(5), Unknown("throttled"), Known(1))
	if decision.Verdict == VerdictWithin {
		t.Fatal("unknown usage must never produce a within verdict")
	}
}

type fixedVCPU struct {
	count int32
	found bool
	err   error
}

func (f fixedVCPU) VCPUCount(string) (int32, bool, error) { return f.count, f.found, f.err }

func change(action model.Action, resourceType string, after map[string]any, unknown map[string]any) model.PlannedChange {
	return model.PlannedChange{Address: resourceType + ".test", ResourceType: resourceType, ProviderName: "aws", Action: action, After: after, AfterUnknown: unknown}
}

// Count quotas add one per created resource, and several creates accumulate.
func TestResourceCountAccumulatesAcrossCreates(t *testing.T) {
	rule := Rule{Resource: "aws_vpc", Consumption: rules.Consumption{Type: rules.ConsumptionResourceCount}}
	changes := []model.PlannedChange{
		change(model.ActionCreate, "aws_vpc", nil, nil),
		change(model.ActionCreate, "aws_vpc", nil, nil),
		change(model.ActionCreate, "aws_subnet", nil, nil),
	}
	measurement := PlannedConsumption(changes, rule, nil)
	if !measurement.Known || measurement.Value != 2 {
		t.Fatalf("measurement = %+v, want 2 for the two VPCs only", measurement)
	}
}

// A destroy does not free capacity for the same apply: Terraform may need the
// room before it gets round to the deletion.
func TestDeletionsDoNotOffsetCreations(t *testing.T) {
	rule := Rule{Resource: "aws_vpc", Consumption: rules.Consumption{Type: rules.ConsumptionResourceCount}}
	changes := []model.PlannedChange{
		change(model.ActionCreate, "aws_vpc", nil, nil),
		change(model.ActionDelete, "aws_vpc", nil, nil),
	}
	measurement := PlannedConsumption(changes, rule, nil)
	if measurement.Value != 1 {
		t.Fatalf("value = %g, want 1; a delete must not be counted as headroom", measurement.Value)
	}
}

// A replacement can hold the old and new resource at once, so it counts as an
// addition rather than as neutral.
func TestReplacementCountsAsAnAddition(t *testing.T) {
	rule := Rule{Resource: "aws_vpc", Consumption: rules.Consumption{Type: rules.ConsumptionResourceCount}}
	measurement := PlannedConsumption([]model.PlannedChange{change(model.ActionReplace, "aws_vpc", nil, nil)}, rule, nil)
	if measurement.Value != 1 {
		t.Fatalf("value = %g, want 1", measurement.Value)
	}
}

// vCPU consumption comes from AWS's own instance type data.
func TestVCPUConsumptionUsesTheResolver(t *testing.T) {
	rule := Rule{Resource: "aws_instance", Consumption: rules.Consumption{Type: rules.ConsumptionVCPU, Field: "instance_type"}}
	changes := []model.PlannedChange{change(model.ActionCreate, "aws_instance", map[string]any{"instance_type": "m6i.2xlarge"}, nil)}
	measurement := PlannedConsumption(changes, rule, fixedVCPU{count: 8, found: true})
	if !measurement.Known || measurement.Value != 8 {
		t.Fatalf("measurement = %+v", measurement)
	}
}

// An instance type Terraform cannot resolve until apply makes the planned
// consumption unknown rather than zero.
func TestUnknownInstanceTypeMakesPlannedConsumptionUnknown(t *testing.T) {
	rule := Rule{Resource: "aws_instance", Consumption: rules.Consumption{Type: rules.ConsumptionVCPU, Field: "instance_type"}}
	changes := []model.PlannedChange{change(model.ActionCreate, "aws_instance", map[string]any{}, map[string]any{"instance_type": true})}
	measurement := PlannedConsumption(changes, rule, fixedVCPU{count: 8, found: true})
	if measurement.Known {
		t.Fatal("an unresolved instance type must make consumption unknown")
	}
}

// If AWS cannot be asked, the answer is unknown rather than zero.
func TestResolverFailureMakesConsumptionUnknown(t *testing.T) {
	rule := Rule{Resource: "aws_instance", Consumption: rules.Consumption{Type: rules.ConsumptionVCPU, Field: "instance_type"}}
	changes := []model.PlannedChange{change(model.ActionCreate, "aws_instance", map[string]any{"instance_type": "m6i.large"}, nil)}
	measurement := PlannedConsumption(changes, rule, fixedVCPU{err: errors.New("AccessDenied")})
	if measurement.Known {
		t.Fatal("a failed lookup must not yield a known consumption")
	}
}

// A resource whose consumption family is unknown cannot contribute a number.
func TestUnknownConsumptionFamilyIsUnknown(t *testing.T) {
	rule := Rule{Resource: "aws_thing", Consumption: rules.Consumption{Type: rules.ConsumptionUnknown}}
	measurement := PlannedConsumption([]model.PlannedChange{change(model.ActionCreate, "aws_thing", nil, nil)}, rule, nil)
	if measurement.Known {
		t.Fatal("an unknown consumption family must not produce a number")
	}
}

// A rule missing any part is not computable, so the pack build can report it
// before the runtime meets it.
func TestComputableRequiresEveryComponent(t *testing.T) {
	complete := Rule{QuotaCode: "L-1", Usage: &UsageMetric{}, Consumption: rules.Consumption{Type: rules.ConsumptionResourceCount}}
	if !complete.Computable() {
		t.Fatal("a complete rule should be computable")
	}
	for name, rule := range map[string]Rule{
		"no quota code":  {Usage: &UsageMetric{}, Consumption: rules.Consumption{Type: rules.ConsumptionResourceCount}},
		"no usage":       {QuotaCode: "L-1", Consumption: rules.Consumption{Type: rules.ConsumptionResourceCount}},
		"no consumption": {QuotaCode: "L-1", Usage: &UsageMetric{}, Consumption: rules.Consumption{Type: rules.ConsumptionUnknown}},
	} {
		if rule.Computable() {
			t.Errorf("%s: rule must not be computable", name)
		}
	}
}

// A determined overrun is the only thing that may block an apply.
func TestOnlyADeterminedOverrunBlocks(t *testing.T) {
	rule := Rule{Resource: "aws_vpc", QuotaCode: "L-F678F1CE", QuotaName: "VPCs per Region", Adjustable: true}
	exceeded := Finding(rule, "aws_vpc.test", Evaluate(Known(5), Known(5), Known(1)))
	if exceeded.Severity != model.SeverityError || exceeded.Confidence != model.ConfidenceHigh {
		t.Fatalf("an overrun should block: %+v", exceeded)
	}
	if !strings.Contains(exceeded.Problem, "VPCs per Region") {
		t.Fatalf("problem should name the quota: %q", exceeded.Problem)
	}
}

// An unknown component produces a coverage note that names what was missing,
// never silence and never a warning or a blocking claim.
func TestUnknownComponentProducesANoteNamingTheGap(t *testing.T) {
	rule := Rule{Resource: "aws_vpc", QuotaCode: "L-F678F1CE", QuotaName: "VPCs per Region"}
	finding := Finding(rule, "aws_vpc.test", Evaluate(Known(5), Unknown("CloudWatch returned no usage datapoints"), Known(1)))
	if finding.Severity != model.SeverityInfo || len(finding.Gaps) != 1 {
		t.Fatalf("severity = %s, gaps %v; want an informational gap", finding.Severity, finding.Gaps)
	}
	if finding.ID != "aws.quota-unverified" {
		t.Fatalf("id = %s", finding.ID)
	}
	if !strings.Contains(finding.Problem, "CloudWatch returned no usage datapoints") {
		t.Fatalf("problem should carry the reason: %q", finding.Problem)
	}
}

// A quota AWS will not raise needs different advice from one the user can ask
// to increase.
func TestRemediationReflectsWhetherTheQuotaIsAdjustable(t *testing.T) {
	adjustable := Finding(Rule{QuotaCode: "L-1", QuotaName: "VPCs per Region", Adjustable: true}, "aws_vpc.test", Evaluate(Known(1), Known(1), Known(1)))
	if !strings.Contains(adjustable.Remediation, "Request an increase") {
		t.Fatalf("adjustable remediation = %q", adjustable.Remediation)
	}
	fixed := Finding(Rule{QuotaCode: "L-2", QuotaName: "Fixed thing", Adjustable: false}, "aws_vpc.test", Evaluate(Known(1), Known(1), Known(1)))
	if !strings.Contains(fixed.Remediation, "cannot be raised") {
		t.Fatalf("fixed remediation = %q", fixed.Remediation)
	}
}
