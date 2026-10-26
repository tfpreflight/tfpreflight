package permissions

import (
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// The invariant this whole design exists to protect: every generated operation
// is either checked, legitimately skipped because the plan decided its
// condition, or counted as a coverage gap. There is no fourth outcome in which
// one simply disappears.
func TestNoOperationDisappearsFromConsideration(t *testing.T) {
	change := model.PlannedChange{
		Address: "aws_thing.test", ResourceType: "aws_thing", ProviderName: "aws", Action: model.ActionCreate,
		After: map[string]any{"tags": map[string]any{"Name": "x"}},
	}
	operations := []packs.OperationRule{
		{Service: "thing", Name: "CreateThing", Permission: "thing:CreateThing", Certainty: "required"},
		{Service: "thing", Name: "NoMapping", Certainty: "required"},
		{Service: "thing", Name: "TagThing", Permission: "thing:TagThing", Certainty: packs.CertaintyConditional, Condition: &packs.OperationCondition{Type: packs.ConditionAttributeSet, Field: "tags"}},
		{Service: "thing", Name: "SkipThing", Permission: "thing:SkipThing", Certainty: packs.CertaintyConditional, Condition: &packs.OperationCondition{Type: packs.ConditionAttributeSet, Field: "absent"}},
		{Service: "thing", Name: "RevokeThing", Permission: "thing:RevokeThing", Certainty: packs.CertaintyConditional, Condition: &packs.OperationCondition{Type: "control-flow"}},
		{Service: "thing", Name: "OpaqueThing", Certainty: packs.CertaintyConditional},
	}
	rules := []packs.ResolvedRule{{Change: change, Action: packs.ActionRule{Operations: operations}}}

	checked := map[string]bool{}
	for _, requirement := range requiredPermissions(rules) {
		checked[requirement.operation.Service+":"+requirement.operation.Name] = true
	}
	unresolved, unevaluable := Gaps(change, rules)
	accounted := map[string]bool{}
	for name := range checked {
		accounted[name] = true
	}
	for _, name := range append(append([]string(nil), unresolved...), unevaluable...) {
		accounted[name] = true
	}
	// Legitimately skipped: the plan positively decided the condition is false.
	for _, operation := range operations {
		name := operation.Service + ":" + operation.Name
		if !accounted[name] && operation.ConditionEvaluable() && !operation.Required(change) {
			accounted[name] = true
		}
	}
	for _, operation := range operations {
		name := operation.Service + ":" + operation.Name
		if !accounted[name] {
			t.Errorf("operation %s was neither checked, deliberately skipped, nor counted as a coverage gap", name)
		}
	}
}

// An unsupported version must say so, not report a clean run.
