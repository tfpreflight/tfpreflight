package conflicts

import (
	"context"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

func logGroupRule() Rule {
	return Rule{ProviderVersion: "6.64.0", ResourceType: "aws_cloudwatch_log_group", IdentityField: "name", LookupService: "cloudwatchlogs", LookupOperation: "DescribeLogGroups", CreateSemantics: SemanticsDuplicateErrorListed, Scope: "account_region", Trust: TrustGenerated}
}

func securityGroupRule() Rule {
	return Rule{
		ProviderVersion: "6.64.0", ResourceType: "aws_security_group", LookupService: "ec2", LookupOperation: "DescribeSecurityGroups",
		CreateSemantics: SemanticsDuplicateErrorListed, Scope: "vpc", Trust: TrustGenerated,
		Identity: Identity{Type: "composite", Parts: []IdentityPart{
			{Attribute: "name", LookupField: "GroupName"},
			{Attribute: "vpc_id", LookupField: "VpcId"},
		}},
	}
}

func TestListedRulesAreChecked(t *testing.T) {
	adapter := &fakeAdapter{service: "cloudwatchlogs", operation: "DescribeLogGroups", outcome: OutcomeExists}
	findings, coverage := resolverWith(logGroupRule(), adapter).Check(context.Background(),
		[]model.PlannedChange{createChange("aws_cloudwatch_log_group", "aws_cloudwatch_log_group.app", map[string]any{"name": "app"}, nil)})
	if len(findings) != 1 || findings[0].Severity != model.SeverityWarning {
		t.Fatalf("a taken log group name must warn (generated trust), got %+v", findings)
	}
	if coverage[0].Status != StatusChecked || adapter.calls != 1 {
		t.Fatalf("coverage = %+v after %d lookups", coverage[0], adapter.calls)
	}
}

func TestFreeLogGroupNameIsAvailable(t *testing.T) {
	adapter := &fakeAdapter{service: "cloudwatchlogs", operation: "DescribeLogGroups", outcome: OutcomeNotFound}
	findings, coverage := resolverWith(logGroupRule(), adapter).Check(context.Background(),
		[]model.PlannedChange{createChange("aws_cloudwatch_log_group", "aws_cloudwatch_log_group.app", map[string]any{"name": "app"}, nil)})
	if len(findings) != 0 || coverage[0].Status != StatusChecked {
		t.Fatalf("findings %v, coverage %+v", findings, coverage[0])
	}
}

func TestSecurityGroupNameIsLookedUpInItsVPC(t *testing.T) {
	var sent LookupRequest
	adapter := &fakeAdapter{service: "ec2", operation: "DescribeSecurityGroups", outcome: OutcomeExists, capture: &sent}
	findings, coverage := resolverWith(securityGroupRule(), adapter).Check(context.Background(),
		[]model.PlannedChange{createChange("aws_security_group", "aws_security_group.web", map[string]any{"name": "web", "vpc_id": "vpc-0123456789abcdef0"}, nil)})
	if sent.Values["GroupName"] != "web" || sent.Values["VpcId"] != "vpc-0123456789abcdef0" {
		t.Fatalf("the lookup was sent %+v: it needs the name and the VPC", sent.Values)
	}
	if len(findings) != 1 || coverage[0].Status != StatusCompositeSupported {
		t.Fatalf("findings %v, coverage %+v", findings, coverage[0])
	}
	if !strings.Contains(findings[0].Brief, "vpc_id = vpc-0123456789abcdef0") {
		t.Errorf("the finding must say which VPC: %q", findings[0].Brief)
	}
}

// With no known VPC the name could be taken in the default VPC or free in a new
// one: the answer is "could not check", never "available".
func TestSecurityGroupWithoutAKnownVPCIsNotChecked(t *testing.T) {
	for name, unknown := range map[string]map[string]any{
		"vpc_id computed at apply": {"vpc_id": true},
		"vpc_id not in the plan":   nil,
	} {
		t.Run(name, func(t *testing.T) {
			adapter := &fakeAdapter{service: "ec2", operation: "DescribeSecurityGroups", outcome: OutcomeNotFound}
			findings, coverage := resolverWith(securityGroupRule(), adapter).Check(context.Background(),
				[]model.PlannedChange{createChange("aws_security_group", "aws_security_group.web", map[string]any{"name": "web"}, unknown)})
			if adapter.calls != 0 || len(findings) != 0 {
				t.Fatalf("%d lookups, findings %v: nothing may be asked without the VPC", adapter.calls, findings)
			}
			if coverage[0].Status != StatusCompositePartUnknown || coverage[0].Status.CheckStatus() != model.CheckUnverifiable {
				t.Fatalf("coverage = %+v, want an unverifiable composite part", coverage[0])
			}
		})
	}
}

// A value the resolver does not know stops the rule before any lookup. A
// tfpreflight from before "duplicate-error-listed" meets that case, which is
// how it skips these rules.
func TestAnUnknownSemanticsValueSendsNoLookup(t *testing.T) {
	rule := logGroupRule()
	rule.CreateSemantics = "a-value-from-the-future"
	adapter := &fakeAdapter{service: "cloudwatchlogs", operation: "DescribeLogGroups", outcome: OutcomeExists}
	findings, coverage := resolverWith(rule, adapter).Check(context.Background(),
		[]model.PlannedChange{createChange("aws_cloudwatch_log_group", "aws_cloudwatch_log_group.app", map[string]any{"name": "app"}, nil)})
	if adapter.calls != 0 || len(findings) != 0 {
		t.Fatalf("%d lookups, findings %v", adapter.calls, findings)
	}
	if coverage[0].Status != StatusSemanticsNotProven || coverage[0].Status.CheckStatus() != model.CheckUnsupported {
		t.Fatalf("coverage = %+v", coverage[0])
	}
}
