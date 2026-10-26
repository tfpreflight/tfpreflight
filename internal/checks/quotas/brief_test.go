package quotas

import (
	"errors"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

func TestEveryFindingHasABrief(t *testing.T) {
	rule := Rule{QuotaName: "VPCs per Region", QuotaCode: "L-F678F1CE", Adjustable: true}
	exceeds := Finding(rule, "aws_vpc.main", Decision{Verdict: VerdictExceeds, Limit: Measurement{Value: 5, Known: true}, Usage: Measurement{Value: 5, Known: true}, Planned: Measurement{Value: 1, Known: true}, Expected: 6})
	if exceeds.Brief != "The VPCs per Region quota (L-F678F1CE) allows 5; the account uses 5 and this plan adds 1." {
		t.Errorf("brief = %q", exceeds.Brief)
	}
	requirement := EC2QuotaRequirement{Change: model.PlannedChange{Address: "aws_instance.big"}, InstanceType: "m6i.32xlarge"}
	launch := quotaExceededFinding(requirement, 128, 64)
	if launch.Brief != "Instance type m6i.32xlarge needs 128 vCPUs; the account's Standard On-Demand quota allows 64." {
		t.Errorf("brief = %q", launch.Brief)
	}
	rule.Adjustable = false
	for _, finding := range []model.Finding{
		exceeds,
		Finding(rule, "aws_vpc.main", Decision{Verdict: VerdictExceeds, Limit: Measurement{Value: 5, Known: true}, Usage: Measurement{Value: 5, Known: true}, Planned: Measurement{Value: 1, Known: true}, Expected: 6}),
		Finding(rule, "aws_vpc.main", Decision{Verdict: VerdictUnknown, Reason: "usage unavailable"}),
		launch,
		quotaUnavailableFinding(requirement, errors.New("throttled")),
	} {
		assertBrief(t, finding)
	}
}

// assertBrief checks a finding's default-output text: one sentence, then one
// line starting "Fix:" or "Check:".
func assertBrief(t *testing.T, finding model.Finding) {
	t.Helper()
	brief, next := finding.Brief, finding.Next
	if brief == "" || !strings.HasSuffix(brief, ".") || strings.ContainsAny(brief, "\n") || strings.Count(strings.TrimSuffix(brief, "."), ". ") > 0 {
		t.Errorf("%s: brief %q is not one sentence", finding.ID, brief)
	}
	if !strings.HasPrefix(next, "Fix: ") && !strings.HasPrefix(next, "Check: ") || strings.Contains(next, "\n") {
		t.Errorf("%s: next %q is not one Fix: or Check: line", finding.ID, next)
	}
}
