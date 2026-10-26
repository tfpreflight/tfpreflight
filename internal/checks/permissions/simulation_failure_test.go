package permissions

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// failingIAMSimulator answers the first `succeed` calls with an implicit deny
// for each action asked, then fails every call with err.
type failingIAMSimulator struct {
	succeed int
	err     error
	empty   bool
	mu      sync.Mutex
	calls   int
}

func (f *failingIAMSimulator) GetContextKeysForPrincipalPolicy(context.Context, *iam.GetContextKeysForPrincipalPolicyInput, ...func(*iam.Options)) (*iam.GetContextKeysForPrincipalPolicyOutput, error) {
	return nil, errors.New("not authorized")
}

func (f *failingIAMSimulator) SimulatePrincipalPolicy(_ context.Context, input *iam.SimulatePrincipalPolicyInput, _ ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
	f.mu.Lock()
	f.calls++
	call := f.calls
	f.mu.Unlock()
	if call <= f.succeed {
		var results []types.EvaluationResult
		for _, action := range input.ActionNames {
			results = append(results, types.EvaluationResult{EvalActionName: aws.String(action), EvalDecision: types.PolicyEvaluationDecisionTypeImplicitDeny})
		}
		return &iam.SimulatePrincipalPolicyOutput{EvaluationResults: results}, nil
	}
	if f.empty {
		return &iam.SimulatePrincipalPolicyOutput{}, nil
	}
	return nil, f.err
}

// A simulation that cannot run is partial coverage for every resource it did
// not decide. It is never an error, decided results are kept, and a failing
// first call stops simulation there.
func TestSimulationFailureLeavesPermissionsPartial(t *testing.T) {
	requirements := fiveLambdaRequirements(t)
	for name, client := range map[string]*failingIAMSimulator{
		"access denied first": {err: &smithy.GenericAPIError{Code: "AccessDenied", Message: "not authorized to perform iam:SimulatePrincipalPolicy"}},
		"throttled midway":    {succeed: 1, err: &smithy.GenericAPIError{Code: "Throttling", Message: "Rate exceeded"}},
		"network":             {succeed: 2, err: errors.New("dial tcp 127.0.0.1:1: connect: connection refused")},
		"no decision":         {succeed: 1, empty: true},
	} {
		t.Run(name, func(t *testing.T) {
			result := simulatePermissions(context.Background(), client, "arn:aws:iam::123456789012:role/apply", testScope, requirements)
			decided := decidedAddresses(result)
			assertSimulationStopped(t, client, decided)
			assertEveryRequirementAccounted(t, requirements, result, decided)
			if len(result.Unchecked) == 0 {
				t.Fatal("nothing unchecked after a failure")
			}
			for _, finding := range UncheckedFindings(result.Unchecked) {
				if finding.Severity != model.SeverityInfo || finding.ID != "aws.permission-simulation-unavailable" {
					t.Fatalf("unchecked finding %+v must be informational", finding)
				}
			}
		})
	}
}

// fiveLambdaRequirements is five functions: five ARNs, five simulations.
func fiveLambdaRequirements(t *testing.T) []plannedPermission {
	t.Helper()
	var requirements []plannedPermission
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		requirement := lambdaCreate(map[string]any{"function_name": name}, nil, "generated")
		requirement.change.Address = "aws_lambda_function." + name
		requirements = append(requirements, requirement)
	}
	batches, _ := batchRequirements(requirements, testScope, loadActions())
	if len(batches) < 3 {
		t.Fatalf("%d batches; the test needs several", len(batches))
	}
	return requirements
}

// decidedAddresses is every resource the simulation reached a decision for.
func decidedAddresses(result Result) map[string]bool {
	decided := map[string]bool{}
	for _, finding := range result.Findings {
		decided[finding.Resource] = true
	}
	for address := range result.Partial {
		decided[address] = true
	}
	return decided
}

// assertSimulationStopped checks that decided results survive a failure and
// that simulation stops at a failing first call, or soon after a later one.
func assertSimulationStopped(t *testing.T, client *failingIAMSimulator, decided map[string]bool) {
	t.Helper()
	if client.succeed > 0 && len(decided) == 0 {
		t.Fatalf("decided results lost after %d successful simulations", client.succeed)
	}
	if client.succeed == 0 && client.calls != 1 {
		t.Fatalf("%d calls; a failing first call must stop simulation", client.calls)
	}
	if client.calls > client.succeed+1+simulationWorkers {
		t.Fatalf("%d calls; simulation must stop soon after the first failure", client.calls)
	}
}

// assertEveryRequirementAccounted checks that each resource is decided or
// unchecked with the simulation-unavailable reason.
func assertEveryRequirementAccounted(t *testing.T, requirements []plannedPermission, result Result, decided map[string]bool) {
	t.Helper()
	for _, requirement := range requirements {
		address := requirement.change.Address
		reason, unchecked := result.Unchecked[address]
		if !unchecked {
			if !decided[address] {
				t.Fatalf("%s is neither decided nor unchecked", address)
			}
			continue
		}
		if !strings.HasPrefix(reason, "permission simulation unavailable: simulating ") || !strings.Contains(reason, " failed: ") {
			t.Fatalf("%s: reason %q", address, reason)
		}
	}
}
