package permissions

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// pagingIAM allows every action, answers per action, a page of pageSize at a
// time, after latency; it counts calls.
type pagingIAM struct {
	latency  time.Duration
	pageSize int
	mu       sync.Mutex
	calls    int
	inputs   []*iam.SimulatePrincipalPolicyInput
}

func (p *pagingIAM) GetContextKeysForPrincipalPolicy(context.Context, *iam.GetContextKeysForPrincipalPolicyInput, ...func(*iam.Options)) (*iam.GetContextKeysForPrincipalPolicyOutput, error) {
	return &iam.GetContextKeysForPrincipalPolicyOutput{}, nil
}

func (p *pagingIAM) SimulatePrincipalPolicy(_ context.Context, input *iam.SimulatePrincipalPolicyInput, _ ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
	time.Sleep(p.latency)
	p.mu.Lock()
	p.calls++
	p.inputs = append(p.inputs, input)
	p.mu.Unlock()
	start := 0
	if input.Marker != nil {
		if _, err := fmt.Sscan(*input.Marker, &start); err != nil {
			return nil, err
		}
	}
	end := len(input.ActionNames)
	if p.pageSize > 0 && start+p.pageSize < end {
		end = start + p.pageSize
	}
	output := &iam.SimulatePrincipalPolicyOutput{}
	for _, action := range input.ActionNames[start:end] {
		decision := types.PolicyEvaluationDecisionTypeAllowed
		if action == "lambda:TagResource" {
			decision = types.PolicyEvaluationDecisionTypeExplicitDeny
		}
		output.EvaluationResults = append(output.EvaluationResults, types.EvaluationResult{EvalActionName: aws.String(action), EvalDecision: decision})
	}
	if end < len(input.ActionNames) {
		output.IsTruncated, output.Marker = true, aws.String(fmt.Sprint(end))
	}
	return output, nil
}

// Every action against one resource ARN with one request context is one
// simulation, read page by page; each action keeps its own decision.
func TestActionsOnOneResourceShareOneSimulation(t *testing.T) {
	var requirements []plannedPermission
	for _, permission := range []string{"lambda:CreateFunction", "lambda:GetFunction", "lambda:TagResource"} {
		requirement := lambdaCreate(map[string]any{"function_name": "api"}, nil, "generated")
		service, name := "lambda", permission[len("lambda:"):]
		requirement.operation = packs.OperationRule{Service: service, Name: name, Permission: permission, Trust: "generated"}
		requirements = append(requirements, requirement)
	}
	client := &pagingIAM{pageSize: 2}
	result := simulatePermissions(context.Background(), client, principal, testScope, requirements)
	// One simulation in two pages, then the blocking deny is checked against
	// "*" on its own.
	if client.calls != 3 || client.inputs[2].ResourceArns[0] != "*" || client.inputs[2].ActionNames[0] != "lambda:TagResource" {
		t.Fatalf("%d calls; want one simulation in two pages and one \"*\" check", client.calls)
	}
	if got := client.inputs[0]; len(got.ActionNames) != 3 || got.ResourceArns[0] != functionARN {
		t.Fatalf("simulated %v against %v", got.ActionNames, got.ResourceArns)
	}
	if len(result.Findings) != 1 || result.Findings[0].Decision != "explicitDeny" || len(result.Unchecked) != 0 {
		t.Fatalf("findings %+v unchecked %v", result.Findings, result.Unchecked)
	}
}

// TestMeasureSimulationSpeed times the permission check of a 200-resource
// plan against an IAM that answers after 100ms. It runs only when asked:
// TFP_MEASURE_SPEED=1.
func TestMeasureSimulationSpeed(t *testing.T) {
	if os.Getenv("TFP_MEASURE_SPEED") == "" {
		t.Skip("set TFP_MEASURE_SPEED=1 to measure")
	}
	pack, loaded, err := packs.LoadRuntimePack("6.64.0")
	if err != nil || !loaded {
		t.Fatalf("pack: %v %v", loaded, err)
	}
	types := []string{"aws_iam_role", "aws_lambda_function", "aws_sqs_queue", "aws_sns_topic", "aws_cloudwatch_log_group", "aws_s3_bucket", "aws_security_group", "aws_ecr_repository", "aws_dynamodb_table", "aws_kms_key"}
	var changes []model.PlannedChange
	for i := 0; i < 200; i++ {
		resourceType := types[i%len(types)]
		name := fmt.Sprintf("svc-%03d", i)
		after := map[string]any{"name": name, "function_name": name, "bucket": name, "tags": map[string]any{"team": "platform"}}
		changes = append(changes, model.PlannedChange{Address: fmt.Sprintf("%s.r%03d", resourceType, i), ResourceType: resourceType, ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate, After: after})
	}
	requirements := requiredPermissions(packs.ResolveRules(pack, changes))
	client := &pagingIAM{latency: 100 * time.Millisecond}
	started := time.Now()
	result := simulatePermissions(context.Background(), client, "arn:aws:iam::123456789012:role/apply", testScope, requirements)
	elapsed := time.Since(started)
	t.Logf("200 resources, %d permission checks: %d SimulatePrincipalPolicy calls, %s (findings %d, unchecked %d)",
		len(requirements), client.calls, elapsed.Round(10*time.Millisecond), len(result.Findings), len(result.Unchecked))
}
