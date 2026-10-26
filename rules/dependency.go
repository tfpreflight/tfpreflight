package rules

import "strings"

// Trust levels, weakest to strongest.
const (
	TrustGenerated       = "generated"
	TrustProviderRuntime = "provider_runtime_proven"
	TrustAWSModel        = "aws_model_proven"
	TrustVerified        = "verified"
)

// Lookup is how to ask AWS whether a target exists by id.
type Lookup struct {
	Service   string `json:"service"`
	Operation string `json:"operation"`
	Field     string `json:"field"`
	// NotFoundCodes are the error codes that prove absence. Without them a
	// lookup can confirm existence but never prove a target missing.
	NotFoundCodes []string `json:"not_found_codes,omitempty"`
	NotFoundType  string   `json:"not_found_type,omitempty"`
}

// ProvesAbsence reports whether a lookup failure can be read as missing.
func (l Lookup) ProvesAbsence() bool { return len(l.NotFoundCodes) > 0 || l.NotFoundType != "" }

// Target identity sources: whether a literal identifier could be the id of
// something this plan creates.
const (
	// IdentityServerGenerated means AWS assigns the id, so no planned create can
	// produce a value already written in configuration.
	IdentityServerGenerated = "server-generated"
	// IdentityUnknown means where the id comes from is not known, so a planned
	// create holding the same literal cannot be ruled out.
	IdentityUnknown = "unknown"
)

// Route is the schema path the rule reads, in parts. An older rule has only its
// dotted attribute.
func (r ExistenceRule) Route() []string {
	if len(r.Path) > 0 {
		return r.Path
	}
	return strings.Split(r.Attribute, ".")
}

// ExistenceRule says a planned attribute must name a target that already exists
// when the operation runs.
type ExistenceRule struct {
	Resource  string `json:"resource"`
	Operation string `json:"operation"`
	// Attribute is the schema path in dotted form, such as
	// vpc_config.subnet_ids, and Path the same path in parts. A block may
	// repeat, so a path is a route through the plan rather than a key.
	Attribute       string   `json:"attribute"`
	Path            []string `json:"path,omitempty"`
	TargetResource  string   `json:"target_resource"`
	TargetAttribute string   `json:"target_attribute"`
	Lookup          Lookup   `json:"lookup"`
	// TargetIdentity is IdentityServerGenerated, IdentityUnknown, or the planned
	// attribute whose value becomes the target's id.
	TargetIdentity string `json:"target_identity"`
	Trust          string `json:"trust"`
	// Key is what the configuration references the target by, and how that value
	// becomes the one the lookup takes.
	Key ReferenceKey `json:"key,omitempty"`
	// Member is the AWS request member the value reaches, such as
	// VpcConfig.SubnetIds.
	Member string `json:"member,omitempty"`
	// CreateService and CreateOperation name the call the create sends this
	// value to: the one that would fail if the target were absent. They are part
	// of an enforcement claim's identity, so a provider release that moves the
	// value to another call does not inherit evidence about the old one.
	CreateService   string `json:"create_service,omitempty"`
	CreateOperation string `json:"create_operation,omitempty"`
	// CreateOperationAlternatives records that the value reaches this member
	// through more than one create operation. Which one a plan makes is not
	// settled, so an observation of one does not describe the others.
	CreateOperationAlternatives bool `json:"create_operation_alternatives,omitempty"`
	// CreateProvenance is how the value was shown to reach the create request:
	// sdkv2_ast, traced through provider source, or framework_model_mapping, a
	// Plugin Framework model matched by AutoFlex's naming rules. They are
	// different evidence, and a provider release can move a resource from one to
	// the other.
	CreateProvenance string `json:"create_provenance,omitempty"`
	// Collection marks a set or list attribute. When it is unknown at plan time,
	// the plan cannot show which identifiers it will hold.
	Collection bool `json:"collection,omitempty"`
	// ScopeAttributes are arguments that move the target into another account or
	// region, such as peer_region next to peer_vpc_id. When one is set, a lookup
	// in the provider's own account and region answers the wrong question.
	ScopeAttributes []string `json:"scope_attributes,omitempty"`
	// HighEligible marks a complete chain. The runtime does not read it:
	// blocking rests only on verified enforcement evidence.
	HighEligible bool   `json:"high_eligible"`
	Evidence     string `json:"evidence"`
}

// EnforcementFingerprint identifies the semantics an observation was made
// against. A change in any part can change what AWS does, and then stored
// evidence describes something else.
type EnforcementFingerprint struct {
	ProviderVersion string `json:"provider_version"`
	Resource        string `json:"resource"`
	Attribute       string `json:"attribute"`
	CreateService   string `json:"create_service"`
	CreateOperation string `json:"create_operation"`
	Member          string `json:"member"`
	TargetResource  string `json:"target_resource"`
	KeyKind         string `json:"key_kind"`
	Normalization   string `json:"normalization"`
	Provenance      string `json:"create_provenance"`
}

// Key is the fingerprint's canonical form. It holds no path, line number or test
// value, so the same semantics give the same key everywhere.
func (f EnforcementFingerprint) Key() string {
	return strings.Join([]string{
		f.ProviderVersion, f.Resource, f.Attribute,
		f.CreateService, f.CreateOperation, f.Member,
		f.TargetResource, f.KeyKind, f.Normalization, f.Provenance,
	}, "|")
}

// Complete reports whether every part of the fingerprint is present. An
// incomplete fingerprint never matches evidence.
func (f EnforcementFingerprint) Complete() bool {
	return f.ProviderVersion != "" && f.Resource != "" && f.Attribute != "" &&
		f.CreateService != "" && f.CreateOperation != "" && f.Member != "" &&
		f.TargetResource != "" && f.KeyKind != ""
}

// Fingerprint is the enforcement fingerprint of one rule.
func (r ExistenceRule) Fingerprint(providerVersion string) EnforcementFingerprint {
	key := r.Key.canonical()
	return EnforcementFingerprint{
		ProviderVersion: providerVersion,
		Resource:        r.Resource,
		Attribute:       r.Attribute,
		CreateService:   r.CreateService,
		CreateOperation: r.CreateOperation,
		Member:          r.Member,
		TargetResource:  r.TargetResource,
		KeyKind:         key.Kind,
		Normalization:   key.Normalization,
		Provenance:      r.CreateProvenance,
	}
}
