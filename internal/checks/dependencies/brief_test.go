package dependencies

import (
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

func TestEveryFindingHasABrief(t *testing.T) {
	rule := ExistenceRule{Resource: "aws_subnet", Attribute: "vpc_id", TargetResource: "aws_vpc", CreateService: "ec2", CreateOperation: "CreateSubnet"}
	missing := missingFinding("aws_subnet.a", rule, "vpc-00000000000000000", BlockingDecision{Blocking: true})
	if missing.Brief != "vpc_id refers to VPC vpc-00000000000000000, which does not exist." || missing.Next != "Fix: correct vpc_id, or create the VPC first." {
		t.Errorf("brief = %q, next = %q", missing.Brief, missing.Next)
	}
	for _, finding := range []*model.Finding{
		missing,
		missingFinding("aws_subnet.a", rule, "vpc-00000000000000000", BlockingDecision{}),
		orderingFinding("aws_subnet.a", rule, "is destroyed by this same plan"),
	} {
		assertBrief(t, *finding)
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
