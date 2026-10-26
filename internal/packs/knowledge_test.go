package packs

import (
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

func resolvedForTest(t *testing.T, changes []model.PlannedChange) []ResolvedRule {
	t.Helper()
	pack, err := loadDefaultPack()
	if err != nil {
		t.Fatal(err)
	}
	return ResolveRules(pack, changes)
}

func TestKnowledgePackGoldenRules(t *testing.T) {
	rules := resolvedForTest(t, []model.PlannedChange{
		{Address: "aws_s3_bucket.test", ResourceType: "aws_s3_bucket", ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate, After: map[string]any{"bucket": "golden-bucket"}},
		{Address: "aws_instance.quota_test", ResourceType: "aws_instance", ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate, After: map[string]any{"instance_type": "m6i.8xlarge", "region": "us-east-1"}},
	})
	if len(rules) != 2 {
		t.Fatalf("resolved rules = %d, want 2", len(rules))
	}
	if rules[0].Action.Operations[0].Permission != "s3:CreateBucket" || rules[0].Action.Conflict.Type != "s3_bucket_exists" {
		t.Fatalf("unexpected S3 golden rule: %#v", rules[0])
	}
	if rules[1].Action.Quota.Type != "ec2_standard_vcpu" {
		t.Fatalf("unexpected EC2 golden rule: %#v", rules[1])
	}
}

// terraform apply refreshes a resource right after creating it, so a create
// change must require the read path's permissions too. Predicting only the
// create permission is what made tfpreflight's sets necessary but not
// sufficient.
func TestCreateRequiresReadAfterCreatePermissions(t *testing.T) {
	pack := KnowledgePack{Resources: map[string]ResourceRule{
		"aws_placement_group": {Actions: map[string]ActionRule{
			"create": {Operations: []OperationRule{{Name: "CreatePlacementGroup", Service: "ec2", Permission: "ec2:CreatePlacementGroup", Certainty: "required"}}},
			"read":   {Operations: []OperationRule{{Name: "DescribePlacementGroups", Service: "ec2", Permission: "ec2:DescribePlacementGroups", Certainty: "required"}}},
		}},
	}}
	rules := ResolveRules(pack, []model.PlannedChange{{ProviderName: "aws", ResourceType: "aws_placement_group", Action: model.ActionCreate}})
	if len(rules) != 1 {
		t.Fatalf("resolved %d rules, want 1", len(rules))
	}
	var permissions []string
	for _, operation := range rules[0].Action.Operations {
		permissions = append(permissions, operation.Permission)
	}
	want := []string{"ec2:CreatePlacementGroup", "ec2:DescribePlacementGroups"}
	if strings.Join(permissions, ",") != strings.Join(want, ",") {
		t.Fatalf("permissions = %v, want %v", permissions, want)
	}
}

// A resource whose read uses the same permission as its create must not report
// that permission twice.
func TestReadAfterCreateDoesNotDuplicatePermissions(t *testing.T) {
	create := ActionRule{Operations: []OperationRule{{Name: "GetThing", Permission: "thing:GetThing"}}}
	read := ActionRule{Operations: []OperationRule{{Name: "GetThing", Permission: "thing:getthing"}}}
	if merged := withReadAfterCreate(create, read); len(merged.Operations) != 1 {
		t.Fatalf("operations = %d, want 1", len(merged.Operations))
	}
}

// A resource with no discovered read path is unchanged.
func TestReadAfterCreateLeavesCreateAloneWhenNoReadIsKnown(t *testing.T) {
	create := ActionRule{Operations: []OperationRule{{Name: "CreateThing", Permission: "thing:CreateThing"}}}
	if merged := withReadAfterCreate(create, ActionRule{}); len(merged.Operations) != 1 {
		t.Fatalf("operations = %d, want 1", len(merged.Operations))
	}
}

// AWS requires the tagging permission on create only when the request actually
// carries tags, so the operation is conditional on the attribute rather than
// always required. Reporting it unconditionally would tell users to grant a
// permission an untagged resource never uses.
func TestCreateTagsIsRequiredOnlyWhenThePlanSetsTags(t *testing.T) {
	tagging := OperationRule{
		Name: "CreateTags", Permission: "ec2:CreateTags", Certainty: CertaintyConditional,
		Condition: &OperationCondition{Type: ConditionAttributeSet, Field: "tags"},
	}

	tagged := model.PlannedChange{After: map[string]any{"tags": map[string]any{"Name": "x"}}}
	if !tagging.Required(tagged) {
		t.Error("a plan that sets tags must require the tagging permission")
	}
	untagged := model.PlannedChange{After: map[string]any{"tags": map[string]any{}}}
	if tagging.Required(untagged) {
		t.Error("an empty tags map must not require the tagging permission")
	}
	absent := model.PlannedChange{After: map[string]any{}}
	if tagging.Required(absent) {
		t.Error("a plan with no tags must not require the tagging permission")
	}
}

// A value terraform cannot know until apply may still turn out to be set, so
// the permission is reported rather than silently dropped.
func TestUnknownTagsStillRequireThePermission(t *testing.T) {
	tagging := OperationRule{
		Name: "CreateTags", Permission: "ec2:CreateTags", Certainty: CertaintyConditional,
		Condition: &OperationCondition{Type: ConditionAttributeSet, Field: "tags"},
	}
	unknown := model.PlannedChange{After: map[string]any{}, AfterUnknown: map[string]any{"tags": true}}
	if !tagging.Required(unknown) {
		t.Error("an unknown tags value must require the tagging permission")
	}
}

// A conditional operation whose condition was never proven stays skipped.
func TestUnprovenConditionalOperationIsStillSkipped(t *testing.T) {
	operation := OperationRule{Name: "PutX", Permission: "svc:PutX", Certainty: CertaintyConditional}
	if operation.Required(model.PlannedChange{After: map[string]any{"tags": map[string]any{"a": "b"}}}) {
		t.Error("a conditional operation with no proven condition must not be required")
	}
}
