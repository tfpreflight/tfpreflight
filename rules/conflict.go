// The schema of the conflict packs. The runtime resolver loads them into its own
// rule type and imports only the create-semantics vocabulary from here.

package rules

import "fmt"

// RuntimeRule is one conflict rule as the packs carry it.
type RuntimeRule struct {
	ProviderVersion   string         `json:"provider_version"`
	ResourceType      string         `json:"resource_type"`
	IdentityField     string         `json:"identity_field"`
	LookupService     string         `json:"lookup_service"`
	LookupOperation   string         `json:"lookup_operation"`
	CreateSemantics   string         `json:"create_semantics"`
	Scope             string         `json:"scope"`
	Trust             string         `json:"trust"`
	Identity          map[string]any `json:"identity,omitempty"`
	SemanticsEvidence map[string]any `json:"semantics_evidence"`
}

// RuntimeRuleFile is the on-disk shape of either pack.
type RuntimeRuleFile struct {
	ProviderVersion string        `json:"provider_version"`
	Rules           []RuntimeRule `json:"rules"`
}

// Create semantics, established per resource.
const (
	// SemanticsDuplicateError means AWS rejects a create whose identity is
	// already taken. Only this justifies a conflict finding.
	SemanticsDuplicateError = "duplicate-error"
	// SemanticsIdempotent means a create over an existing identity succeeds.
	SemanticsIdempotent = "idempotent"
	// SemanticsUpsert means a create updates the existing object.
	SemanticsUpsert = "upsert"
	// SemanticsInconclusive means the duplicate case was never proven.
	SemanticsInconclusive = "inconclusive"
)

// compilerFamilyDuplicate is the conflict family the pack build emits for a
// duplicate identity, named here to avoid importing the build's code.
const compilerFamilyDuplicate = "duplicate_conflict"

// RuntimeSemantics translates a pack build conflict family into the vocabulary
// the resolver matches on. A family the resolver does not implement is an error,
// not a default: a rule whose semantics nothing honours must not ship.
func RuntimeSemantics(family string) (string, error) {
	switch family {
	case compilerFamilyDuplicate:
		return SemanticsDuplicateError, nil
	default:
		return "", fmt.Errorf("conflict family %q has no runtime semantics; add the mapping deliberately rather than defaulting", family)
	}
}

// ProjectRuntimeRules converts accepted pack build rules into runtime rules.
// Only the create-semantics vocabulary changes. Trust passes through, so a
// generated rule stays generated and a projection can never promote a warning to
// a blocking finding.
func ProjectRuntimeRules(rules []RuntimeRule) ([]RuntimeRule, error) {
	projected := make([]RuntimeRule, 0, len(rules))
	for _, rule := range rules {
		semantics, err := RuntimeSemantics(rule.CreateSemantics)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", rule.ResourceType, err)
		}
		rule.CreateSemantics = semantics
		projected = append(projected, rule)
	}
	return projected, nil
}
