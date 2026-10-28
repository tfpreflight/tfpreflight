package aws

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/plan"
)

// withProviderSource points the readers that look at the provider block at a
// main.tf holding it.
func withProviderSource(t *testing.T, sources contextSources, attributes string) contextSources {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte("provider \"aws\" {\n  region = \"eu-west-1\"\n"+attributes+"\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sources.AssumeRoleVariable = func() (string, bool, error) { return plan.AssumeRoleVariable(dir) }
	sources.AssumeRoleLocal = func() (string, string, bool, error) { return plan.ProviderLocal(dir, "assume_role", "role_arn") }
	sources.ExternalIDVariable = func() (string, bool, error) { return plan.ProviderVariable(dir, "assume_role", "external_id") }
	sources.ExternalIDLocal = func() (string, string, bool, error) { return plan.ProviderLocal(dir, "assume_role", "external_id") }
	sources.AllowedAccountsList = func() ([]plan.StringListItem, string, bool, error) {
		return plan.ProviderStringList(dir, "", "allowed_account_ids")
	}
	return sources
}

// planWith is the context plan with extra provider block expressions, and the
// given recorded variables as JSON object members.
func planWith(expressions, variables string) []byte {
	data := string(contextPlanRegion(`{"constant_value":"eu-west-1"}` + expressions))
	return []byte(replaceOnce(data, `"variables":{"region":{"value":"eu-west-1"}}`, `"variables":{`+variables+`}`))
}

const (
	deployRole     = "arn:aws:iam::999999999999:role/deploy"
	secretExternal = "s3cr3t-external-id"
	plainVariables = `"region":{"value":"eu-west-1"}`
)

// assume_role.role_arn and external_id accept what the region does: a literal,
// a bare variable, or a local set to a plain string. The external ID reaches
// the AssumeRole call, and is never printed.
func TestAssumeRoleSettingsFromVariablesAndLocals(t *testing.T) {
	for name, tc := range map[string]assumeCase{
		"role from a local": {
			providerBlock: "assume_role {\n    role_arn = local.role\n  }\n}\nlocals {\n  role = \"" + deployRole + "\"",
			assumeRole:    `{"role_arn":{"references":["local.role"]}}`, variables: plainVariables,
			wantRole: deployRole, wantSource: IdentityFromAssumeRole + " (local.role)",
		},
		"role from a local built from a variable": {
			providerBlock: "assume_role {\n    role_arn = local.role\n  }\n}\nlocals {\n  role = var.deploy_role",
			assumeRole:    `{"role_arn":{"references":["local.role"]}}`, variables: plainVariables,
			wantGap: "the provider's assume_role.role_arn is computed from local.role",
		},
		"external ID from a variable": {
			providerBlock: "assume_role {\n    role_arn = \"" + deployRole + "\"\n    external_id = var.external_id\n  }",
			assumeRole:    `{"role_arn":{"constant_value":"` + deployRole + `"},"external_id":{"references":["var.external_id"]}}`,
			variables:     plainVariables + `,"external_id":{"value":"` + secretExternal + `"}`,
			wantRole:      deployRole, wantSource: IdentityFromAssumeRole, wantExternalID: secretExternal,
		},
		"external ID from a local": {
			providerBlock: "assume_role {\n    role_arn = \"" + deployRole + "\"\n    external_id = local.external\n  }\n}\nlocals {\n  external = \"" + secretExternal + "\"",
			assumeRole:    `{"role_arn":{"constant_value":"` + deployRole + `"},"external_id":{"references":["local.external"]}}`, variables: plainVariables,
			wantRole: deployRole, wantSource: IdentityFromAssumeRole, wantExternalID: secretExternal,
		},
		"role and external ID both from variables": {
			providerBlock: "assume_role {\n    role_arn = var.deploy_role\n    external_id = var.external_id\n  }",
			assumeRole:    `{"role_arn":{"references":["var.deploy_role"]},"external_id":{"references":["var.external_id"]}}`,
			variables:     plainVariables + `,"deploy_role":{"value":"` + deployRole + `"},"external_id":{"value":"` + secretExternal + `"}`,
			wantRole:      deployRole, wantSource: IdentityFromAssumeRole + " (var.deploy_role)", wantExternalID: secretExternal,
		},
		// The role is still named, and so is the apply identity; only the
		// inspection checks that need to assume it are left out.
		"external ID variable without a value": {
			providerBlock: "assume_role {\n    role_arn = \"" + deployRole + "\"\n    external_id = var.external_id\n  }",
			assumeRole:    `{"role_arn":{"constant_value":"` + deployRole + `"},"external_id":{"references":["var.external_id"]}}`, variables: plainVariables,
			wantRole: deployRole, wantSource: IdentityFromAssumeRole,
			wantGap: "the provider's assume_role.external_id is var.external_id but the plan records no value for it",
		},
		"external ID built by a function": {
			providerBlock: "assume_role {\n    role_arn = \"" + deployRole + "\"\n    external_id = format(\"%s\", var.external_id)\n  }",
			assumeRole:    `{"role_arn":{"constant_value":"` + deployRole + `"},"external_id":{"references":["var.external_id"]}}`,
			variables:     plainVariables + `,"external_id":{"value":"` + secretExternal + `"}`,
			wantRole:      deployRole, wantSource: IdentityFromAssumeRole,
			wantGap: "the provider's assume_role.external_id is an expression of var.external_id, not the variable itself",
		},
	} {
		t.Run(name, func(t *testing.T) {
			var calls []assumeCall
			sources := withProviderSource(t, identitySources("arn:aws:iam::123456789012:user/inspector", func(string) error { return nil }, &calls), tc.providerBlock)
			run := resolveRunContext(context.Background(), sources, planWith(`,"assume_role":[`+tc.assumeRole+`]`, tc.variables), "")
			assertAssumeRun(t, tc, run, calls)
		})
	}
}

// assumeCase is one way of writing the provider's assume_role block, and what
// the run should make of it.
type assumeCase struct {
	providerBlock  string
	assumeRole     string // the assume_role block's expressions in the plan
	variables      string
	wantRole       string
	wantSource     string
	wantExternalID string
	wantGap        string // part of why inspection is unavailable
}

func assertAssumeRun(t *testing.T, tc assumeCase, run RunContext, calls []assumeCall) {
	t.Helper()
	identity := run.Identity
	if tc.wantRole != "" && (!identity.ApplyIdentityKnown || identity.ApplyIdentity != tc.wantRole || identity.ApplyIdentitySource != tc.wantSource) {
		t.Errorf("apply identity %q from %q (known %v), want %q from %q", identity.ApplyIdentity, identity.ApplyIdentitySource, identity.ApplyIdentityKnown, tc.wantRole, tc.wantSource)
	}
	switch {
	case tc.wantGap != "":
		if !strings.Contains(run.InspectionUnavailable, tc.wantGap) || len(calls) != 0 {
			t.Errorf("inspection unavailable %q (assume calls %+v), want it to say %q", run.InspectionUnavailable, calls, tc.wantGap)
		}
	case !run.Inspects() || len(calls) != 1 || calls[0].role != deployRole || calls[0].externalID != tc.wantExternalID:
		t.Errorf("inspection unavailable %q, assume calls %+v; want one call for %s with external ID %q", run.InspectionUnavailable, calls, deployRole, tc.wantExternalID)
	}
	for _, shown := range []string{run.Unresolved, run.InspectionUnavailable, identity.ApplyIdentityNote} {
		if strings.Contains(shown, secretExternal) {
			t.Errorf("the external ID appears in %q", shown)
		}
	}
}

// allowed_account_ids accepts the same: a literal list, a list variable, a list
// whose elements are literals, variables or plain-string locals, or a local
// set to a list of literals. The run inspects only an account in it.
func TestAllowedAccountsFromVariablesAndLocals(t *testing.T) {
	inspector := "arn:aws:iam::" + contextTestAccount + ":user/inspector"
	const notAllowed = "inspection account does not satisfy provider allowed_account_ids"
	for name, tc := range map[string]struct {
		providerBlock string
		references    string // allowed_account_ids' references in the plan
		variables     string
		want          string // the run's unresolved reason; empty when it resolves
	}{
		"list variable with the account": {
			providerBlock: `allowed_account_ids = var.accounts`, references: `["var.accounts"]`,
			variables: plainVariables + `,"accounts":{"value":["` + contextTestAccount + `","999999999999"]}`,
		},
		"list variable without the account": {
			providerBlock: `allowed_account_ids = var.accounts`, references: `["var.accounts"]`,
			variables: plainVariables + `,"accounts":{"value":["999999999999"]}`, want: notAllowed,
		},
		"list of one variable": {
			providerBlock: `allowed_account_ids = [var.account]`, references: `["var.account"]`,
			variables: plainVariables + `,"account":{"value":"` + contextTestAccount + `"}`,
		},
		"list of a literal and a variable": {
			providerBlock: `allowed_account_ids = ["999999999999", var.account]`, references: `["var.account"]`,
			variables: plainVariables + `,"account":{"value":"` + contextTestAccount + `"}`,
		},
		"list of a plain-string local": {
			providerBlock: "allowed_account_ids = [local.account]\n}\nlocals {\n  account = \"" + contextTestAccount + "\"", references: `["local.account"]`,
			variables: plainVariables,
		},
		"local list of literals": {
			providerBlock: "allowed_account_ids = local.accounts\n}\nlocals {\n  accounts = [\"" + contextTestAccount + "\"]", references: `["local.accounts"]`,
			variables: plainVariables,
		},
		"local list of literals without the account": {
			providerBlock: "allowed_account_ids = local.accounts\n}\nlocals {\n  accounts = [\"999999999999\"]", references: `["local.accounts"]`,
			variables: plainVariables, want: notAllowed,
		},
		"variable missing from the plan": {
			providerBlock: `allowed_account_ids = var.accounts`, references: `["var.accounts"]`, variables: plainVariables,
			want: "provider allowed_account_ids is var.accounts but the plan records no value for it",
		},
		"variable that is not a list": {
			providerBlock: `allowed_account_ids = var.accounts`, references: `["var.accounts"]`,
			variables: plainVariables + `,"accounts":{"value":"` + contextTestAccount + `"}`,
			want:      "provider allowed_account_ids is var.accounts but its value in the plan is not a list of strings",
		},
		"list variable with a number": {
			providerBlock: `allowed_account_ids = var.accounts`, references: `["var.accounts"]`,
			variables: plainVariables + `,"accounts":{"value":[123456789012]}`,
			want:      "provider allowed_account_ids is var.accounts but its value in the plan is not a list of strings",
		},
		"element variable missing from the plan": {
			providerBlock: `allowed_account_ids = [var.account]`, references: `["var.account"]`, variables: plainVariables,
			want: "provider allowed_account_ids includes var.account but the plan records no value for it",
		},
		"element variable that is empty": {
			providerBlock: `allowed_account_ids = [var.account]`, references: `["var.account"]`,
			variables: plainVariables + `,"account":{"value":""}`,
			want:      "provider allowed_account_ids includes var.account but its value in the plan is not a non-empty string",
		},
		"function": {
			providerBlock: `allowed_account_ids = concat(var.a, var.b)`, references: `["var.a","var.b"]`,
			variables: plainVariables + `,"a":{"value":["` + contextTestAccount + `"]},"b":{"value":[]}`,
			want:      "provider allowed_account_ids is computed from var.a, var.b" + onlyPlainLists,
		},
	} {
		t.Run(name, func(t *testing.T) {
			sources := withProviderSource(t, contextSourcesFor(inspector), tc.providerBlock)
			run := resolveRunContext(context.Background(), sources, planWith(`,"allowed_account_ids":{"references":`+tc.references+`}`, tc.variables), "")
			if run.Unresolved != tc.want {
				t.Fatalf("unresolved %q, want %q", run.Unresolved, tc.want)
			}
		})
	}
}

// Without the provider block's source, a variable list cannot be confirmed to
// be written as the plan suggests, so the run is not guessed.
func TestAllowedAccountsNeedTheSource(t *testing.T) {
	sources := contextSourcesFor("arn:aws:iam::" + contextTestAccount + ":user/inspector")
	run := resolveRunContext(context.Background(), sources, planWith(`,"allowed_account_ids":{"references":["var.accounts"]}`, plainVariables+`,"accounts":{"value":["`+contextTestAccount+`"]}`), "")
	const want = "provider allowed_account_ids references var.accounts but the provider block source is unavailable to confirm how it is written"
	if run.Unresolved != want {
		t.Fatalf("unresolved %q, want %q", run.Unresolved, want)
	}
}
