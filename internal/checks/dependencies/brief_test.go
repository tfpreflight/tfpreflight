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
	// A warning says what AWS answered and the case in which apply could still
	// succeed; only a verified, blocking finding states that the target is gone.
	warned := missingFinding("aws_subnet.a", rule, "vpc-00000000000000000", BlockingDecision{})
	if want := "AWS can't find VPC vpc-00000000000000000 in this account and region; unless it is in another account, apply will fail."; warned.Brief != want {
		t.Errorf("warning brief = %q, want %q", warned.Brief, want)
	}
	groupRule := ExistenceRule{Resource: "aws_vpc_security_group_ingress_rule", Attribute: "referenced_security_group_id", TargetResource: "aws_security_group"}
	group := missingFinding("aws_vpc_security_group_ingress_rule.a", groupRule, "sg-0123456789abcdef0", BlockingDecision{})
	if want := "AWS can't find security group sg-0123456789abcdef0 in this account and region; unless it is in a peered VPC or another account, apply will fail."; group.Brief != want {
		t.Errorf("security group brief = %q, want %q", group.Brief, want)
	}
	if blocked := missingFinding("aws_subnet.a", rule, "vpc-00000000000000000", BlockingDecision{Blocking: true}); strings.Contains(blocked.Brief, "unless") {
		t.Errorf("a blocking finding names an exception: %q", blocked.Brief)
	}
	for _, finding := range []*model.Finding{
		missing,
		group,
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
