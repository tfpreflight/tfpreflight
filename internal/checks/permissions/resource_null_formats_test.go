package permissions

import (
	"encoding/json"
	"testing"
)

// AWS's service reference sometimes lists a resource type with no ARN format
// (the pack holds "formats": null). That must read as "no ARN known": the
// action is simulated against "*" and the check says why, never a crash and
// never an ARN made up.
func TestResourceTypeWithNullARNFormatsFallsBackToStar(t *testing.T) {
	var file struct {
		Actions map[string]iamAction `json:"actions"`
	}
	const document = `{"actions": {
		"ivs:getstage": {"resources": [{"type": "Stage-Logging-Configuration", "formats": null}]}
	}}`
	if err := json.Unmarshal([]byte(document), &file); err != nil {
		t.Fatalf("null formats did not load: %v", err)
	}
	for name, tc := range map[string]struct {
		permission, resourceType string
		after                    map[string]any
	}{
		// The planned resource is the null-formats type itself.
		"own type": {"ivs:GetStage", "aws_ivs_stage_logging_configuration", map[string]any{"name": "x"}},
		// The plan names another resource, and the first resource type has none.
		"other type": {"ivs:GetStage", "aws_other_thing", map[string]any{"name": "x"}},
		// Nothing in the plan, no ARN formats anywhere.
		"empty plan": {"ivs:GetStage", "aws_other_thing", nil},
	} {
		t.Run(name, func(t *testing.T) {
			r := verifiedPermission("x.y", tc.resourceType, tc.permission, tc.after)
			got := targetFor(r, testScope, file.Actions)
			if got.ARN != "*" || got.Exact || got.Reason == "" {
				t.Errorf("target = %+v, want \"*\", not exact, with a reason", got)
			}
		})
	}
}
