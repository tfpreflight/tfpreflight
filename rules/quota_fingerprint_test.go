package rules

import "testing"

func TestCounterFingerprintTracksCounterSemanticsOnly(t *testing.T) {
	base := Rule{Resource: "aws_thing", ServiceCode: "example", QuotaCode: "L-1", Scope: ScopeRegion, Consumption: Consumption{Type: ConsumptionResourceCount, Units: 1}, Counter: &UsageCounter{Adapter: "example:ListThings", Operation: "ListThings", Collection: "Things", Pagination: "paginator"}}
	changed := base
	changed.Counter = &UsageCounter{Adapter: "example:ListOtherThings", Operation: "ListOtherThings", Collection: "Things", Pagination: "paginator"}
	if SemanticFingerprint(base) == SemanticFingerprint(changed) {
		t.Fatal("counter operation must change quota fingerprint")
	}
	permissionOnly := base
	permissionOnly.Evidence = "an IAM permission changed elsewhere"
	if SemanticFingerprint(base) != SemanticFingerprint(permissionOnly) {
		t.Fatal("non-quota evidence must not change quota fingerprint")
	}
}
