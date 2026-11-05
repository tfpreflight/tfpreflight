package dependencies

import (
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

// Only a partial result is listed; each kind of reason gets its own wording,
// and a resource with two partial rules gets one note with two gaps.
func TestCoverageGapsListEveryPartialResultWithItsReason(t *testing.T) {
	results := []Result{
		{Address: "a.one", Attribute: "vpc_id", Verdict: VerdictSatisfied},
		{Address: "a.one", Attribute: "role", Verdict: VerdictPartial, Reason: "role is not known until apply"},
		{Address: "a.one", Attribute: "group", Verdict: VerdictPartial, Reason: "the target could not be inspected: " + ReasonNoLookupCode + "x/Y/Z", Cause: CauseNoLookup},
		{Address: "a.two", Attribute: "key", Verdict: VerdictPartial, Reason: "the target could not be inspected: AWS inspection error: UnauthorizedOperation", Cause: CauseNoAnswer},
	}
	notes := CoverageGaps(results)
	if len(notes) != 2 || notes[0].Resource != "a.one" || notes[1].Resource != "a.two" {
		t.Fatalf("want one note each for a.one and a.two, got %+v", notes)
	}
	if got := len(notes[0].Gaps); got != 2 {
		t.Fatalf("a.one has %d gaps, want 2", got)
	}
	wants := []struct{ summary, why string }{
		{"role: role is not known until apply", "plan does not hold enough"},
		{"group: ", "Install the newest tfpreflight release"},
		{"key: ", "no usable answer"},
	}
	gaps := append(append([]model.Gap(nil), notes[0].Gaps...), notes[1].Gaps...)
	for i, want := range wants {
		if !strings.HasPrefix(gaps[i].Summary, want.summary) || !strings.Contains(gaps[i].Why, want.why) {
			t.Errorf("gap %d = %+v, want summary %q and why containing %q", i, gaps[i], want.summary, want.why)
		}
	}
	for _, note := range notes {
		if note.Severity != model.SeverityInfo {
			t.Errorf("a coverage note must be information only: %+v", note)
		}
	}
}
