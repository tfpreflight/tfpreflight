package permissions

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

func TestVerifiedEvidencePromotesOnlyExactTuple(t *testing.T) {
	pack, loaded, err := packs.LoadRuntimePack(testProviderVersion)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded {
		t.Fatal("generated pack was not loaded")
	}
	queue := pack.Resources["aws_sqs_queue"].Actions["create"].Operations
	if len(queue) == 0 || queue[0].Trust != "verified" {
		t.Fatalf("queue trust = %#v", queue)
	}
	// A neighbouring generated resource is not promoted merely because it uses
	// the same service or a similar operation.
	networkInterface := pack.Resources["aws_network_interface"].Actions["create"].Operations
	if len(networkInterface) == 0 || networkInterface[0].Trust != "generated" {
		t.Fatalf("network interface trust = %#v", networkInterface)
	}
}

func TestVerifiedRuntimeEvidenceProducesBlockingFinding(t *testing.T) {
	pack, _, err := packs.LoadRuntimePack(testProviderVersion)
	if err != nil {
		t.Fatal(err)
	}
	change := model.PlannedChange{Address: "aws_sqs_queue.test", ResourceType: "aws_sqs_queue", ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate, After: map[string]any{"name": "orders"}}
	requirements := requiredPermissions(packs.ResolveRules(pack, []model.PlannedChange{change}))
	// A create also requires its read path, so the verified create permission
	// arrives alongside generated read permissions. The verified one must still
	// be present and carry verified trust.
	var verified []plannedPermission
	for _, requirement := range requirements {
		if requirement.operation.Trust == "verified" {
			verified = append(verified, requirement)
		}
	}
	if len(verified) != 1 || verified[0].operation.Permission != "sqs:CreateQueue" {
		t.Fatalf("verified requirements = %#v (of %d total)", verified, len(requirements))
	}
	requirements = verified
	client := &fakeIAMSimulator{decision: types.PolicyEvaluationDecisionTypeImplicitDeny}
	result := simulatePermissions(context.Background(), client, "arn:aws:iam::123456789012:role/test", testScope, requirements)
	findings := result.Findings
	if len(result.Unchecked) != 0 || len(result.Partial) != 0 {
		t.Fatal(result.Unchecked, result.Partial)
	}
	if got := client.input.ResourceArns[0]; got != "arn:aws:sqs:us-east-1:123456789012:orders" {
		t.Fatalf("simulated against %s", got)
	}
	if len(findings) != 1 || findings[0].Severity != model.SeverityError || findings[0].Confidence != model.ConfidenceHigh {
		t.Fatalf("findings = %#v", findings)
	}
}
