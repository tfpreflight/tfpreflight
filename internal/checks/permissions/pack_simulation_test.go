package permissions

import (
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// Generated operations must be simulated, not skipped: an operation marked
// conditional is excluded from simulation, and a pack that marked them all so
// would check nothing.
const testProviderVersion = "6.64.0"

func TestGeneratedOperationsAreCheckedNotSilentlySkipped(t *testing.T) {
	pack, _, err := packs.LoadRuntimePack(testProviderVersion)
	if err != nil {
		t.Fatal(err)
	}
	rule := pack.Resources["aws_subnet"]
	simulated := 0
	for _, operation := range rule.Actions["create"].Operations {
		if operation.Certainty == "" {
			t.Fatalf("operation carries no certainty: %#v", operation)
		}
		// Some conditional operations are legitimate; a resource with no
		// unconditional one is not, because nothing about it would be checked.
		if operation.Certainty != packs.CertaintyConditional && operation.Permission != "" {
			simulated++
		}
	}
	if simulated == 0 {
		t.Fatalf("no create operation would be simulated for aws_subnet: %#v", rule.Actions["create"].Operations)
	}
	change := model.PlannedChange{Address: "aws_subnet.test", ResourceType: "aws_subnet", ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate}
	requirements := requiredPermissions(packs.ResolveRules(pack, []model.PlannedChange{change}))
	if len(requirements) == 0 {
		t.Fatal("a generated create operation produced no permission to simulate")
	}
	if requirements[0].operation.Permission != "ec2:CreateSubnet" {
		t.Fatalf("simulated permission = %q", requirements[0].operation.Permission)
	}
}

// TestUnknownCertaintyIsStillChecked covers a pack that does not state
// certainty: it must fall back to unknown, which is still simulated, rather
// than to conditional, which is not.

func TestUnknownCertaintyIsStillChecked(t *testing.T) {
	pack := packs.KnowledgePack{Resources: map[string]packs.ResourceRule{"aws_thing": {ResourceLabel: "aws_thing", Actions: map[string]packs.ActionRule{"create": {Operations: []packs.OperationRule{
		{Name: "CreateThing", Permission: "svc:CreateThing", Certainty: packs.CertaintyUnknown},
	}}}}}}
	change := model.PlannedChange{Address: "aws_thing.test", ResourceType: "aws_thing", ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate}
	if requirements := requiredPermissions(packs.ResolveRules(pack, []model.PlannedChange{change})); len(requirements) != 1 {
		t.Fatalf("an unknown-certainty operation produced %d requirements, want 1", len(requirements))
	}
	if packs.CertaintyUnknown == packs.CertaintyConditional {
		t.Fatal("unknown certainty must not be the value that skips simulation")
	}
}

// TestConditionalCertaintyIsStillSkipped keeps the original intent: a call the
// provider only makes under some configurations must not be reported missing.

func TestConditionalCertaintyIsStillSkipped(t *testing.T) {
	pack := packs.KnowledgePack{Resources: map[string]packs.ResourceRule{"aws_thing": {ResourceLabel: "aws_thing", Actions: map[string]packs.ActionRule{"create": {Operations: []packs.OperationRule{
		{Name: "MaybeCall", Permission: "svc:MaybeCall", Certainty: packs.CertaintyConditional},
		{Name: "AlwaysCall", Permission: "svc:AlwaysCall", Certainty: packs.CertaintyRequired},
	}}}}}}
	change := model.PlannedChange{Address: "aws_thing.test", ResourceType: "aws_thing", ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate}
	requirements := requiredPermissions(packs.ResolveRules(pack, []model.PlannedChange{change}))
	if len(requirements) != 1 {
		t.Fatalf("expected only the required operation, got %d", len(requirements))
	}
	if requirements[0].operation.Permission != "svc:AlwaysCall" {
		t.Fatalf("simulated %q, want svc:AlwaysCall", requirements[0].operation.Permission)
	}
}
