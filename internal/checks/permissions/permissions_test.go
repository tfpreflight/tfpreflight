package permissions

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/tfpreflight/tfpreflight/internal/packs"
	packdata "github.com/tfpreflight/tfpreflight/packs"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

type fakeIAMSimulator struct {
	// input is the first simulation; inputs every one.
	input          *iam.SimulatePrincipalPolicyInput
	inputs         []*iam.SimulatePrincipalPolicyInput
	decision       types.PolicyEvaluationDecisionType
	missingContext []string
}

func (f *fakeIAMSimulator) GetContextKeysForPrincipalPolicy(context.Context, *iam.GetContextKeysForPrincipalPolicyInput, ...func(*iam.Options)) (*iam.GetContextKeysForPrincipalPolicyOutput, error) {
	return &iam.GetContextKeysForPrincipalPolicyOutput{}, nil
}

func (f *fakeIAMSimulator) SimulatePrincipalPolicy(_ context.Context, input *iam.SimulatePrincipalPolicyInput, _ ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
	if f.input == nil {
		f.input = input
	}
	f.inputs = append(f.inputs, input)
	return &iam.SimulatePrincipalPolicyOutput{EvaluationResults: []types.EvaluationResult{{EvalDecision: f.decision, MissingContextValues: f.missingContext}}}, nil
}

func TestRequiredPermissionsComeFromKnowledgeRules(t *testing.T) {
	requirements := requiredPermissions(resolvedForTest(t, []model.PlannedChange{
		{ResourceType: "aws_s3_bucket", ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate},
		{ResourceType: "aws_s3_bucket", ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionDelete},
		{ResourceType: "aws_instance", ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate},
	}))
	if len(requirements) != 2 || requirements[0].operation.Permission != "s3:CreateBucket" || requirements[1].operation.Permission != "ec2:RunInstances" {
		t.Fatalf("unexpected requirements: %#v", requirements)
	}
}

func TestSimulatePermissionsProducesFindingForDeny(t *testing.T) {
	for _, decision := range []types.PolicyEvaluationDecisionType{
		types.PolicyEvaluationDecisionTypeImplicitDeny,
		types.PolicyEvaluationDecisionTypeExplicitDeny,
	} {
		t.Run(string(decision), func(t *testing.T) {
			client := &fakeIAMSimulator{decision: decision}
			principal := "arn:aws:iam::123456789012:role/tfpreflight-test-role"
			requirements := requiredPermissions(resolvedForTest(t, []model.PlannedChange{{Address: "aws_s3_bucket.test", ResourceType: "aws_s3_bucket", ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate, After: map[string]any{"bucket": "app-logs"}}}))

			result := simulatePermissions(context.Background(), client, principal, testScope, requirements)
			assertDenyFinding(t, client, principal, decision, result)
		})
	}
}

// assertDenyFinding checks one denied create was simulated against the
// bucket's ARN and reported as a blocking finding with its explanation.
func assertDenyFinding(t *testing.T, client *fakeIAMSimulator, principal string, decision types.PolicyEvaluationDecisionType, result Result) {
	t.Helper()
	findings := result.Findings
	if len(result.Unchecked) != 0 || len(result.Partial) != 0 {
		t.Fatalf("simulatePermissions left resources unchecked: %v %v", result.Unchecked, result.Partial)
	}
	if client.input.ResourceArns[0] != "arn:aws:s3:::app-logs" || findings[0].Decision != string(decision) {
		t.Fatalf("simulated %v, decision %q", client.input.ResourceArns, findings[0].Decision)
	}
	if len(findings) != 1 || findings[0].Severity != model.SeverityError || findings[0].Title != "Apply will likely fail" {
		t.Fatalf("unexpected findings: %#v", findings)
	}
	if client.input == nil || *client.input.PolicySourceArn != principal || client.input.ActionNames[0] != "s3:CreateBucket" {
		t.Fatalf("unexpected simulator input: %#v", client.input)
	}
	if findings[0].Operation != "Create an S3 bucket" || findings[0].DecisionExplanation == "" || len(findings[0].Notes) != 1 {
		t.Fatalf("missing explanation fields: %#v", findings[0])
	}
}

// resolvedForTest resolves the shipped pack for a set of planned changes, which
// is how the runtime builds the rules this package consumes.
// resolvedForTest resolves against the hand-written default pack, the same
// pack these tests used before the runtime was split into packages.
func resolvedForTest(t *testing.T, changes []model.PlannedChange) []packs.ResolvedRule {
	t.Helper()
	data, err := packdata.AWS.ReadFile("aws/knowledge/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack packs.KnowledgePack
	if err := json.Unmarshal(data, &pack); err != nil {
		t.Fatal(err)
	}
	return packs.ResolveRules(pack, changes)
}

var testScope = Scope{Partition: "aws", Region: "us-east-1", Account: "123456789012"}
