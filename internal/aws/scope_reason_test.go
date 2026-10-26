package aws

import (
	"fmt"
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/checks/dependencies"
)

// The scope's reason, for every combination of the five things that can rule
// out inspecting: when several apply, the allowed_account_ids mismatch wins,
// then a different profile, then a missing account, then the provider
// context's own reason, then the region's.
func TestResolveScopeReasonPrecedence(t *testing.T) {
	for i := 0; i < 48; i++ {
		name, in, want := scopeReasonCase(i)
		t.Run(name, func(t *testing.T) {
			if got := resolveScope(in).Reason; got != want {
				t.Errorf("reason = %q, want %q", got, want)
			}
		})
	}
}

// scopeReasonCase decodes combination i of: region unresolved, provider
// context unresolved, account known, profile differs (one bit each), and no,
// a satisfied or an unsatisfied allowed_account_ids (i / 16).
func scopeReasonCase(i int) (string, scopeInputs, string) {
	regionUnresolved, providerUnresolved, accountKnown, profileDiffers := i&1 != 0, i&2 != 0, i&4 != 0, i&8 != 0
	restriction := []string{"no restriction", "account allowed", "account not allowed"}[i/16]
	accounts := map[string][]string{"account allowed": {"123456789012"}, "account not allowed": {"999999999999"}}[restriction]
	in := scopeInputs{Provider: dependencies.ProviderContext{RegionKind: dependencies.RegionLiteral, Region: "eu-west-1", AllowedAccounts: accounts}, Profile: "dev"}
	want := ""
	if regionUnresolved {
		in.Provider.RegionKind, in.Provider.Region = dependencies.RegionOther, ""
		want = "provider region is an expression tfpreflight cannot evaluate; only a literal, a bare variable, or a local set to a plain string can be resolved"
	}
	if providerUnresolved {
		in.Provider.Reason = "provider context requires unsupported configuration: endpoints"
		want = in.Provider.Reason
	}
	if accountKnown {
		in.InspectionIdentity = "arn:aws:iam::123456789012:user/inspector"
	} else {
		want = "inspection account identity unavailable"
	}
	if profileDiffers {
		in.Provider.Profile = "prod"
		want = "Terraform provider profile differs from inspection profile; account equivalence unproven"
	}
	// An unknown account satisfies no allowed_account_ids.
	if restriction == "account not allowed" || (restriction == "account allowed" && !accountKnown) {
		want = "inspection account does not satisfy provider allowed_account_ids"
	}
	name := fmt.Sprintf("region unresolved %v, provider unresolved %v, account known %v, profile differs %v, %s",
		regionUnresolved, providerUnresolved, accountKnown, profileDiffers, restriction)
	return name, in, want
}
