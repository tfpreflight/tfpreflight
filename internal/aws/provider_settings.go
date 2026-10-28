package aws

import (
	"slices"
	"strings"

	"github.com/tfpreflight/tfpreflight/internal/checks/dependencies"
)

// providerExternalID is the external ID the provider assumes its role with: a
// literal, var.<name> from the value the plan recorded, or local.<name> set to a
// plain string. It is empty when the provider sets none. The reason never holds
// the ID, only the names it came from.
func providerExternalID(provider dependencies.ProviderContext, variable func() (string, bool, error), local func() (string, string, bool, error)) (id, reason string) {
	assume := provider.AssumeRole
	if assume == nil {
		return "", ""
	}
	if len(assume.ExternalIDReferences) == 0 {
		return assume.ExternalID, ""
	}
	const subject = "the provider's assume_role.external_id"
	if name, single := singleLocal(assume.ExternalIDReferences); single {
		id, _, reason = valueFromLocal(subject, name, local)
		return id, reason
	}
	id, _, reason = valueFromVariable(subject, assume.ExternalIDReferences, variable, provider.Variables)
	return id, reason
}

// onlyPlainLists ends every reason allowed_account_ids could not be resolved.
const onlyPlainLists = "; only a list of literals, bare variables and locals set to plain strings, or one such variable or local, can be resolved"

// resolveAllowedAccounts decides the accounts the provider allows. A constant
// list is taken as it is. One that references other values is read from the
// provider block's source and the plan's variables: exactly var.<name> holding
// a list of strings, exactly a local written as a list of literals, or a list
// whose elements are each a literal, a variable or a local set to a plain
// string. Anything else is unresolved: a guess could let the run inspect an
// account the provider refuses.
func resolveAllowedAccounts(in scopeInputs) (accounts []string, reason string) {
	provider := in.Provider
	references := provider.AllowedAccountsReferences
	if len(references) == 0 {
		return provider.AllowedAccounts, ""
	}
	const subject = "provider allowed_account_ids"
	named := strings.Join(references, ", ")
	if in.AllowedAccountsList == nil {
		return nil, subject + " references " + named + " but the provider block source is unavailable to confirm how it is written"
	}
	items, wholeVar, ok, err := in.AllowedAccountsList()
	switch {
	case err != nil:
		return nil, subject + " references " + named + " but the provider block could not be read: " + err.Error()
	case !ok:
		return nil, subject + " is computed from " + named + onlyPlainLists
	case wholeVar != "":
		if !slices.Equal(references, []string{"var." + wholeVar}) {
			return nil, subject + " is computed from " + named + onlyPlainLists
		}
		return accountsFromListVariable(subject, wholeVar, provider.Variables)
	}
	accounts = []string{}
	for _, item := range items {
		if item.Value != "" {
			accounts = append(accounts, item.Value)
			continue
		}
		if !slices.Contains(references, "var."+item.Var) {
			return nil, subject + " is computed from " + named + onlyPlainLists
		}
		recorded, present := provider.Variables[item.Var]
		if !present {
			return nil, subject + " includes var." + item.Var + " but the plan records no value for it"
		}
		text, isText := recorded.(string)
		if !isText || text == "" {
			return nil, subject + " includes var." + item.Var + " but its value in the plan is not a non-empty string"
		}
		accounts = append(accounts, text)
	}
	return accounts, ""
}

// accountsFromListVariable reads allowed_account_ids = var.<name> from the list
// of strings the plan recorded.
func accountsFromListVariable(subject, name string, variables map[string]any) ([]string, string) {
	recorded, present := variables[name]
	if !present {
		return nil, subject + " is var." + name + " but the plan records no value for it"
	}
	values, isList := recorded.([]any)
	if !isList {
		return nil, subject + " is var." + name + " but its value in the plan is not a list of strings"
	}
	accounts := make([]string, 0, len(values))
	for _, value := range values {
		text, isText := value.(string)
		if !isText || text == "" {
			return nil, subject + " is var." + name + " but its value in the plan is not a list of strings"
		}
		accounts = append(accounts, text)
	}
	return accounts, ""
}
