package universal

import (
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

func TestEveryFindingHasABrief(t *testing.T) {
	findings := Run([]model.PlannedChange{
		{Address: "a.destroyed", Action: model.ActionDelete},
		{Address: "a.replaced", Action: model.ActionReplace},
		{Address: "a.created", Action: model.ActionCreate, AfterUnknown: map[string]any{"id": true}},
	})
	if len(findings) != 3 {
		t.Fatalf("findings = %+v", findings)
	}
	for _, finding := range findings {
		assertBrief(t, finding)
	}
}

// assertBrief checks a finding's default-output text: one sentence, then one
// line starting "Fix:" or "Check:".
func assertBrief(t *testing.T, finding model.Finding) {
	t.Helper()
	brief, next := finding.Brief, finding.Next
	if brief == "" || !strings.HasSuffix(brief, ".") || strings.ContainsAny(brief, "\n") || strings.Count(strings.TrimSuffix(brief, "."), ". ") > 0 {
		t.Errorf("%s: brief %q is not one sentence", finding.ID, brief)
	}
	if !strings.HasPrefix(next, "Fix: ") && !strings.HasPrefix(next, "Check: ") || strings.Contains(next, "\n") {
		t.Errorf("%s: next %q is not one Fix: or Check: line", finding.ID, next)
	}
}
