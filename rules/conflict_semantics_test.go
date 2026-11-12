package rules

import "testing"

func TestRuntimeSemanticsKnowsBothDuplicateFamilies(t *testing.T) {
	for family, want := range map[string]string{
		"duplicate_conflict":        SemanticsDuplicateError,
		"duplicate_conflict_listed": SemanticsDuplicateErrorListed,
	} {
		got, err := RuntimeSemantics(family)
		if err != nil || got != want {
			t.Errorf("RuntimeSemantics(%q) = %q, %v; want %q", family, got, err, want)
		}
	}
	if _, err := RuntimeSemantics("a_family_nothing_honours"); err == nil {
		t.Error("an unknown family must be refused, not defaulted")
	}
}

// Only a duplicate error justifies a finding; the listed form must stay one
// distinct value so that an older binary, which does not know it, refuses it.
func TestListedSemanticsIsADistinctValue(t *testing.T) {
	if SemanticsDuplicateErrorListed == SemanticsDuplicateError {
		t.Fatal("the listed form must differ from the plain one, or older binaries would run it")
	}
}
