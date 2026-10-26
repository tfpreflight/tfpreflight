package permissions

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// policyIAM decides each simulation with a policy written as a function.
type policyIAM struct {
	decide      func(input *iam.SimulatePrincipalPolicyInput) (types.PolicyEvaluationDecisionType, []string)
	contextKeys []string
	inputs      []*iam.SimulatePrincipalPolicyInput
}

func (p *policyIAM) GetContextKeysForPrincipalPolicy(context.Context, *iam.GetContextKeysForPrincipalPolicyInput, ...func(*iam.Options)) (*iam.GetContextKeysForPrincipalPolicyOutput, error) {
	return &iam.GetContextKeysForPrincipalPolicyOutput{ContextKeyNames: p.contextKeys}, nil
}

func (p *policyIAM) SimulatePrincipalPolicy(_ context.Context, input *iam.SimulatePrincipalPolicyInput, _ ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
	p.inputs = append(p.inputs, input)
	decision, missing := p.decide(input)
	return &iam.SimulatePrincipalPolicyOutput{EvaluationResults: []types.EvaluationResult{{EvalDecision: decision, MissingContextValues: missing}}}, nil
}

func contextValue(input *iam.SimulatePrincipalPolicyInput, name string) []string {
	for _, entry := range input.ContextEntries {
		if *entry.ContextKeyName == name {
			return entry.ContextKeyValues
		}
	}
	return nil
}

const principal = "arn:aws:iam::123456789012:role/deploy"

func lambdaCreate(after map[string]any, unknown map[string]any, trust string) plannedPermission {
	return plannedPermission{
		change:        model.PlannedChange{Address: "aws_lambda_function.api", ResourceType: "aws_lambda_function", Action: model.ActionCreate, After: after, AfterUnknown: unknown},
		resourceLabel: "Lambda function", operationLabel: "Create",
		operation:  packs.OperationRule{Service: "lambda", Name: "CreateFunction", Permission: "lambda:CreateFunction", Certainty: packs.CertaintyRequired, Trust: trust},
		attributes: []string{"function_name", "role", "tags"},
		siblings:   []packs.OperationRule{{Service: "lambda", Name: "CreateFunction", Permission: "lambda:CreateFunction"}},
	}
}

const functionARN = "arn:aws:lambda:us-east-1:123456789012:function:api"

func allowOnly(arn string) func(*iam.SimulatePrincipalPolicyInput) (types.PolicyEvaluationDecisionType, []string) {
	return func(input *iam.SimulatePrincipalPolicyInput) (types.PolicyEvaluationDecisionType, []string) {
		if input.ResourceArns[0] == arn {
			return types.PolicyEvaluationDecisionTypeAllowed, nil
		}
		return types.PolicyEvaluationDecisionTypeImplicitDeny, nil
	}
}

// A policy that allows the action only on this function's ARN allows it; a
// "*" simulation would have reported a denial.
func TestResourceScopedAllowIsAllowed(t *testing.T) {
	client := &policyIAM{decide: allowOnly(functionARN)}
	result := simulatePermissions(context.Background(), client, principal, testScope, []plannedPermission{lambdaCreate(map[string]any{"function_name": "api"}, nil, "generated")})
	if len(result.Findings) != 0 || len(result.Partial) != 0 {
		t.Fatalf("findings %+v, partial %v", result.Findings, result.Partial)
	}
	if got := client.inputs[0].ResourceArns[0]; got != functionARN {
		t.Fatalf("simulated against %s", got)
	}
	if got := contextValue(client.inputs[0], "aws:RequestedRegion"); len(got) != 1 || got[0] != "us-east-1" {
		t.Fatalf("aws:RequestedRegion = %v", got)
	}
}

// A name unknown until apply leaves the ARN unbuilt: "*" is simulated, and a
// denial there is partial, never a finding.
func TestUnknownARNPartIsPartialNotDenied(t *testing.T) {
	client := &policyIAM{decide: allowOnly(functionARN)}
	result := simulatePermissions(context.Background(), client, principal, testScope, []plannedPermission{lambdaCreate(map[string]any{}, map[string]any{"function_name": true}, "verified")})
	if len(result.Findings) != 0 {
		t.Fatalf("a denial against \"*\" was reported: %+v", result.Findings)
	}
	reason := result.Partial["aws_lambda_function.api"]
	if client.inputs[0].ResourceArns[0] != "*" || !strings.Contains(reason, "may be denied") || !strings.Contains(reason, "might allow this resource specifically") {
		t.Fatalf("partial = %q, simulated %v", reason, client.inputs[0].ResourceArns)
	}
	// Allowed against "*" is allowed.
	allowAll := &policyIAM{decide: func(*iam.SimulatePrincipalPolicyInput) (types.PolicyEvaluationDecisionType, []string) {
		return types.PolicyEvaluationDecisionTypeAllowed, nil
	}}
	result = simulatePermissions(context.Background(), allowAll, principal, testScope, []plannedPermission{lambdaCreate(map[string]any{}, map[string]any{"function_name": true}, "verified")})
	if len(result.Findings) != 0 || len(result.Partial) != 0 {
		t.Fatalf("allowed against \"*\": %+v %v", result.Findings, result.Partial)
	}
}

// A policy that allows creation only with a team tag allows a resource the
// plan tags that way.
func TestTagConditionedAllow(t *testing.T) {
	client := &policyIAM{decide: func(input *iam.SimulatePrincipalPolicyInput) (types.PolicyEvaluationDecisionType, []string) {
		if team := contextValue(input, "aws:RequestTag/team"); len(team) == 1 && team[0] == "platform" {
			return types.PolicyEvaluationDecisionTypeAllowed, nil
		}
		return types.PolicyEvaluationDecisionTypeImplicitDeny, nil
	}}
	after := map[string]any{"function_name": "api", "tags": map[string]any{"team": "platform", "env": "prod"}}
	result := simulatePermissions(context.Background(), client, principal, testScope, []plannedPermission{lambdaCreate(after, nil, "generated")})
	if len(result.Findings) != 0 || len(result.Partial) != 0 {
		t.Fatalf("tag-conditioned allow: %+v %v", result.Findings, result.Partial)
	}
	if keys := contextValue(client.inputs[0], "aws:TagKeys"); strings.Join(keys, ",") != "env,team" {
		t.Fatalf("aws:TagKeys = %v", keys)
	}
}

func passRole(after map[string]any) plannedPermission {
	r := lambdaCreate(after, nil, "generated")
	r.operation = packs.OperationRule{Service: "iam", Name: "PassRole", Permission: "iam:PassRole", Trust: "generated"}
	return r
}

// iam:PassRole is simulated against the role the plan names, passed to the
// service that creates the resource.
func TestPassRoleWithPassedToService(t *testing.T) {
	roleARN := "arn:aws:iam::123456789012:role/app"
	client := &policyIAM{contextKeys: []string{"iam:PassedToService"}, decide: func(input *iam.SimulatePrincipalPolicyInput) (types.PolicyEvaluationDecisionType, []string) {
		service := contextValue(input, "iam:PassedToService")
		if input.ResourceArns[0] == roleARN && len(service) == 1 && service[0] == "lambda.amazonaws.com" {
			return types.PolicyEvaluationDecisionTypeAllowed, nil
		}
		return types.PolicyEvaluationDecisionTypeImplicitDeny, nil
	}}
	result := simulatePermissions(context.Background(), client, principal, testScope, []plannedPermission{passRole(map[string]any{"function_name": "api", "role": roleARN})})
	if len(result.Findings) != 0 || len(result.Partial) != 0 {
		t.Fatalf("PassRole: %+v %v (simulated %v)", result.Findings, result.Partial, client.inputs[0].ResourceArns)
	}
	// Denied, with the policy testing a service tfpreflight inferred: partial.
	deny := &policyIAM{contextKeys: []string{"iam:PassedToService"}, decide: func(*iam.SimulatePrincipalPolicyInput) (types.PolicyEvaluationDecisionType, []string) {
		return types.PolicyEvaluationDecisionTypeImplicitDeny, nil
	}}
	result = simulatePermissions(context.Background(), deny, principal, testScope, []plannedPermission{passRole(map[string]any{"function_name": "api", "role": roleARN})})
	if len(result.Findings) != 0 || !strings.Contains(result.Partial["aws_lambda_function.api"], "iam:PassedToService") {
		t.Fatalf("PassRole denial resting on an inferred service: %+v %v", result.Findings, result.Partial)
	}
}

// AWS saying the decision needs context the plan does not give makes it
// partial, never denied.
func TestMissingContextIsPartial(t *testing.T) {
	client := &policyIAM{decide: func(*iam.SimulatePrincipalPolicyInput) (types.PolicyEvaluationDecisionType, []string) {
		return types.PolicyEvaluationDecisionTypeImplicitDeny, []string{"aws:SourceIp"}
	}}
	result := simulatePermissions(context.Background(), client, principal, testScope, []plannedPermission{lambdaCreate(map[string]any{"function_name": "api"}, nil, "verified")})
	if len(result.Findings) != 0 || !strings.Contains(result.Partial["aws_lambda_function.api"], "aws:SourceIp") {
		t.Fatalf("missing context: %+v %v", result.Findings, result.Partial)
	}
}

// An explicit deny on a required call blocks even when the operation rule was
// generated: no IAM allow can override it.
func TestExplicitDenyIsRecorded(t *testing.T) {
	client := &policyIAM{decide: func(*iam.SimulatePrincipalPolicyInput) (types.PolicyEvaluationDecisionType, []string) {
		return types.PolicyEvaluationDecisionTypeExplicitDeny, nil
	}}
	result := simulatePermissions(context.Background(), client, principal, testScope, []plannedPermission{lambdaCreate(map[string]any{"function_name": "api"}, nil, "generated")})
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %+v", result.Findings)
	}
	f := result.Findings[0]
	if f.Decision != "explicitDeny" || f.Severity != model.SeverityError || !strings.Contains(f.Notes[0], functionARN) {
		t.Fatalf("finding = %+v", f)
	}
}

// A verified permission denied on the built ARN but allowed against "*" is
// not blocking: no block rests on an ARN tfpreflight built.
func TestVerifiedDenialOnBuiltARNAloneDoesNotBlock(t *testing.T) {
	client := &policyIAM{decide: func(input *iam.SimulatePrincipalPolicyInput) (types.PolicyEvaluationDecisionType, []string) {
		if input.ResourceArns[0] == "*" {
			return types.PolicyEvaluationDecisionTypeAllowed, nil
		}
		return types.PolicyEvaluationDecisionTypeExplicitDeny, nil
	}}
	result := simulatePermissions(context.Background(), client, principal, testScope, []plannedPermission{lambdaCreate(map[string]any{"function_name": "api"}, nil, "verified")})
	if len(result.Findings) != 1 || result.Findings[0].Severity != model.SeverityWarning {
		t.Fatalf("findings = %+v", result.Findings)
	}
	// Denied both ways, it blocks as it always has.
	both := &policyIAM{decide: func(*iam.SimulatePrincipalPolicyInput) (types.PolicyEvaluationDecisionType, []string) {
		return types.PolicyEvaluationDecisionTypeExplicitDeny, nil
	}}
	result = simulatePermissions(context.Background(), both, principal, testScope, []plannedPermission{lambdaCreate(map[string]any{"function_name": "api"}, nil, "verified")})
	if len(result.Findings) != 1 || result.Findings[0].Severity != model.SeverityError {
		t.Fatalf("findings = %+v", result.Findings)
	}
}
