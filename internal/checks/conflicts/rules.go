package conflicts

// RuleFile is the versioned conflict knowledge for one provider version.
type RuleFile struct {
	ProviderVersion string `json:"provider_version"`
	Rules           []struct {
		Rule
		SemanticsEvidence map[string]any `json:"semantics_evidence,omitempty"`
	} `json:"rules"`
}
