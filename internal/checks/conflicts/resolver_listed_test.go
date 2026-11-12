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

func groupInNewVPC(name string) model.PlannedChange {
	change := createChange("aws_security_group", "aws_security_group.web", map[string]any{"name": name}, map[string]any{"vpc_id": true})
	change.CreatedHere = map[string]bool{"vpc_id": true}
	return change
}

// A group in a VPC this plan creates cannot clash with one that is there: the
// VPC is new and empty. Nothing is asked and nothing is reported as unchecked.
func TestSecurityGroupInANewVPCCannotConflict(t *testing.T) {
	adapter := &fakeAdapter{service: "ec2", operation: "DescribeSecurityGroups", outcome: OutcomeExists}
	findings, coverage := resolverWith(securityGroupRule(), adapter).Check(context.Background(), []model.PlannedChange{groupInNewVPC("web")})
	if adapter.calls != 0 || len(findings) != 0 {
		t.Fatalf("%d lookups, findings %v", adapter.calls, findings)
	}
	if coverage[0].Status != StatusNoConflictPossible || coverage[0].Status.CheckStatus() != model.CheckNotApplicable {
		t.Fatalf("coverage = %+v: a new VPC must not leave a partial line", coverage[0])
	}
}

// A generated name is unknown too, and a new VPC is still empty.
func TestSecurityGroupWithAGeneratedNameInANewVPCCannotConflict(t *testing.T) {
	change := groupInNewVPC("")
	change.After = map[string]any{}
	change.AfterUnknown = map[string]any{"vpc_id": true, "name": true}
	_, coverage := resolverWith(securityGroupRule(), &fakeAdapter{}).Check(context.Background(), []model.PlannedChange{change})
	if coverage[0].Status != StatusNoConflictPossible {
		t.Fatalf("coverage = %+v", coverage[0])
	}
}

// Every new VPC already holds a group named default, so that name is the one
// case a new VPC can clash. It is not looked up (the VPC has no id yet) and is
// reported as not checked.
func TestTheDefaultGroupNameInANewVPCIsNotWaved(t *testing.T) {
	for _, name := range []string{"default", "Default"} {
		adapter := &fakeAdapter{service: "ec2", operation: "DescribeSecurityGroups", outcome: OutcomeNotFound}
		_, coverage := resolverWith(securityGroupRule(), adapter).Check(context.Background(), []model.PlannedChange{groupInNewVPC(name)})
		if adapter.calls != 0 || coverage[0].Status != StatusCompositePartUnknown {
			t.Errorf("%q: %d lookups, coverage %+v", name, adapter.calls, coverage[0])
		}
	}
}

// Only a scope the plan creates is waved through: an unset vpc_id (the default
// VPC) stays "not checked".
func TestSecurityGroupWithoutAMarkedVPCStaysNotChecked(t *testing.T) {
	change := groupInNewVPC("web")
	change.CreatedHere = nil
	_, coverage := resolverWith(securityGroupRule(), &fakeAdapter{}).Check(context.Background(), []model.PlannedChange{change})
	if coverage[0].Status != StatusCompositePartUnknown {
		t.Fatalf("coverage = %+v", coverage[0])
	}
}

// The new-scope rule is for scoped rules only: a log group is never skipped.
func TestANewScopeNeverSkipsAnUnscopedRule(t *testing.T) {
	change := createChange("aws_cloudwatch_log_group", "aws_cloudwatch_log_group.app", map[string]any{"name": "app"}, nil)
	change.CreatedHere = map[string]bool{"vpc_id": true}
	adapter := &fakeAdapter{service: "cloudwatchlogs", operation: "DescribeLogGroups", outcome: OutcomeExists}
	findings, _ := resolverWith(logGroupRule(), adapter).Check(context.Background(), []model.PlannedChange{change})
	if adapter.calls != 1 || len(findings) != 1 {
		t.Fatalf("%d lookups, %d findings", adapter.calls, len(findings))
	}
}
