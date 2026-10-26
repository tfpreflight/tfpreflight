package permissions

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// recordedIAM replays SimulatePrincipalPolicy results from testdata. A result
// is returned only for the exact request it was recorded for: action,
// resource and context. Any other request fails the test, so the replay also
// checks what tfpreflight sends.
type recordedIAM struct {
	t           *testing.T
	ContextKeys []string `json:"context_keys"`
	Exchanges   []struct {
		Action   string                 `json:"action"`
		Resource string                 `json:"resource"`
		Context  map[string][]string    `json:"context"`
		Result   types.EvaluationResult `json:"result"`
	} `json:"exchanges"`
}

func loadRecordedIAM(t *testing.T, name string) *recordedIAM {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "recorded-iam", name))
	if err != nil {
		t.Fatal(err)
	}
	recorded := &recordedIAM{t: t}
	if err := json.Unmarshal(data, recorded); err != nil {
		t.Fatal(err)
	}
	return recorded
}

func (r *recordedIAM) GetContextKeysForPrincipalPolicy(context.Context, *iam.GetContextKeysForPrincipalPolicyInput, ...func(*iam.Options)) (*iam.GetContextKeysForPrincipalPolicyOutput, error) {
	return &iam.GetContextKeysForPrincipalPolicyOutput{ContextKeyNames: r.ContextKeys}, nil
}

func (r *recordedIAM) SimulatePrincipalPolicy(_ context.Context, input *iam.SimulatePrincipalPolicyInput, _ ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
	sent := map[string][]string{}
	for _, entry := range input.ContextEntries {
		sent[*entry.ContextKeyName] = entry.ContextKeyValues
	}
	for _, exchange := range r.Exchanges {
		if len(input.ActionNames) != 1 || !strings.EqualFold(input.ActionNames[0], exchange.Action) || input.ResourceArns[0] != exchange.Resource || !sameContext(sent, exchange.Context) {
			continue
		}
		return &iam.SimulatePrincipalPolicyOutput{EvaluationResults: []types.EvaluationResult{exchange.Result}}, nil
	}
	r.t.Errorf("no recorded IAM result for %v on %v with context %v", input.ActionNames, input.ResourceArns, sent)
	return nil, errors.New("not recorded")
}

func sameContext(sent, recorded map[string][]string) bool {
	if len(sent) != len(recorded) {
		return false
	}
	for name, values := range recorded {
		if !slices.Equal(sent[name], values) {
			return false
		}
	}
	return true
}

// requirementFor is the 6.69.1 rules' requirement for permission on change.
func requirementFor(t *testing.T, change model.PlannedChange, permission string) plannedPermission {
	t.Helper()
	pack, loaded, err := packs.LoadRuntimePack("6.69.1")
	if err != nil || !loaded {
		t.Fatalf("load 6.69.1 rules: loaded=%t err=%v", loaded, err)
	}
	change.ProviderName, change.Action = "registry.terraform.io/hashicorp/aws", model.ActionCreate
	for _, requirement := range requiredPermissions(packs.ResolveRules(pack, []model.PlannedChange{change})) {
		if requirement.operation.Permission == permission {
			return requirement
		}
	}
	t.Fatalf("6.69.1 rules do not require %s for %s", permission, change.ResourceType)
	return plannedPermission{}
}

// onlyFinding checks the explicit deny is one visible finding, never hidden as
// partial or unchecked, and returns it.
func onlyFinding(t *testing.T, result Result) model.Finding {
	t.Helper()
	if len(result.Partial) != 0 || len(result.Unchecked) != 0 {
		t.Fatalf("explicit deny hidden: partial=%v unchecked=%v", result.Partial, result.Unchecked)
	}
	if len(result.Findings) != 1 || result.Findings[0].Decision != "explicitDeny" {
		t.Fatalf("findings = %+v", result.Findings)
	}
	return result.Findings[0]
}

// The demo: the security group's ID is assigned at create, so the request uses
// "*", and the deploy role's explicit deny on "*" must block even though the
// operation rule is generated.
func TestExplicitDenyOnStarBlocks(t *testing.T) {
	requirement := requirementFor(t, model.PlannedChange{
		Address: "aws_security_group.missing_permission", ResourceType: "aws_security_group",
		After:        map[string]any{"name": "blocked", "vpc_id": "vpc-unknown-until-apply"},
		AfterUnknown: map[string]any{"id": true},
	}, "ec2:CreateSecurityGroup")
	if requirement.operation.Trust != "generated" || requirement.operation.Certainty != packs.CertaintyRequired {
		t.Fatalf("operation = %+v, want a required generated rule", requirement.operation)
	}
	result := simulatePermissions(context.Background(), loadRecordedIAM(t, "security-group-create-explicit-deny.json"), principal, testScope, []plannedPermission{requirement})
	f := onlyFinding(t, result)
	if f.Severity != model.SeverityError || !strings.Contains(f.Notes[0], "Simulated against *") || !strings.HasPrefix(f.Remediation, "Remove or narrow") {
		t.Fatalf("finding = %+v", f)
	}
	// The recorded deny is in the role's own policy, so the fix names the role.
	if f.Brief != "The apply role is not allowed to run ec2:CreateSecurityGroup." || f.Next != `Fix: remove or narrow the deny on role "deploy".` {
		t.Fatalf("brief = %q, next = %q", f.Brief, f.Next)
	}
}

// IAM listing context values it lacked means the deny may not apply to the
// real request: a visible warning, not a block and not partial.
func TestExplicitDenyWithMissingContextWarns(t *testing.T) {
	requirement := requirementFor(t, model.PlannedChange{
		Address: "aws_lambda_function.api", ResourceType: "aws_lambda_function",
		After: map[string]any{"function_name": "api"},
	}, "lambda:CreateFunction")
	result := simulatePermissions(context.Background(), loadRecordedIAM(t, "lambda-create-tag-deny.json"), principal, testScope, []plannedPermission{requirement})
	f := onlyFinding(t, result)
	if f.Severity != model.SeverityWarning || !strings.Contains(strings.Join(f.Notes, " "), "request context the plan does not give (aws:RequestTag/team)") {
		t.Fatalf("finding = %+v", f)
	}
}

// A call the provider makes only in some cases may not be made at all: its
// explicit deny is a warning.
func TestExplicitDenyOnConditionalCallWarns(t *testing.T) {
	requirement := requirementFor(t, model.PlannedChange{
		Address: "aws_security_group.tagged", ResourceType: "aws_security_group",
		After:        map[string]any{"name": "tagged", "tags": map[string]any{"team": "platform"}},
		AfterUnknown: map[string]any{"id": true},
	}, "ec2:CreateTags")
	if requirement.operation.Certainty != packs.CertaintyConditional {
		t.Fatalf("operation = %+v, want a conditional rule", requirement.operation)
	}
	result := simulatePermissions(context.Background(), loadRecordedIAM(t, "security-group-tags-explicit-deny.json"), principal, testScope, []plannedPermission{requirement})
	f := onlyFinding(t, result)
	if f.Severity != model.SeverityWarning || !strings.Contains(strings.Join(f.Notes, " "), "only in some cases") {
		t.Fatalf("finding = %+v", f)
	}
}

// An operation of unknown certainty is not known to run: a warning.
func TestExplicitDenyOnUnknownCertaintyWarns(t *testing.T) {
	operation := packs.OperationRule{Permission: "lambda:CreateFunction", Certainty: packs.CertaintyUnknown, Trust: "generated"}
	if reason, check := explicitDenyDoubt(operation, nil, nil, nil); !strings.Contains(reason, "does not say whether") || !strings.HasPrefix(check, "Check: ") {
		t.Fatalf("reason = %q, check = %q", reason, check)
	}
}

// The plan's tags are sent as request context, so a deny unless team=platform
// does not fire for a function tagged team=platform, whether the tag is the
// resource's own or a provider default. Tagged otherwise, it blocks.
func TestTagConditionedDenySatisfiedByPlanDoesNotBlock(t *testing.T) {
	recorded := loadRecordedIAM(t, "lambda-create-tag-deny.json")
	for name, after := range map[string]map[string]any{
		"own tag":     {"function_name": "api", "tags": map[string]any{"team": "platform"}, "tags_all": map[string]any{"team": "platform"}},
		"default tag": {"function_name": "api", "tags": nil, "tags_all": map[string]any{"team": "platform"}},
	} {
		requirement := requirementFor(t, model.PlannedChange{Address: "aws_lambda_function.api", ResourceType: "aws_lambda_function", After: after}, "lambda:CreateFunction")
		result := simulatePermissions(context.Background(), recorded, principal, testScope, []plannedPermission{requirement})
		if len(result.Findings) != 0 || len(result.Partial) != 0 {
			t.Fatalf("%s: findings=%+v partial=%v", name, result.Findings, result.Partial)
		}
	}
	requirement := requirementFor(t, model.PlannedChange{
		Address: "aws_lambda_function.api", ResourceType: "aws_lambda_function",
		After: map[string]any{"function_name": "api", "tags": map[string]any{"team": "data"}, "tags_all": map[string]any{"team": "data"}},
	}, "lambda:CreateFunction")
	result := simulatePermissions(context.Background(), recorded, principal, testScope, []plannedPermission{requirement})
	if f := onlyFinding(t, result); f.Severity != model.SeverityError {
		t.Fatalf("finding = %+v", f)
	}
}
