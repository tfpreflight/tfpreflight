package dependencies

import (
	"github.com/tfpreflight/tfpreflight/rules"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// Families of dependency failure: each way the environment around a planned
// change can make the apply fail.
const (
	FamilyExistence         = "referenced_resource_existence"
	FamilyState             = "referenced_resource_state"
	FamilyParentChild       = "parent_child_relationship"
	FamilyAssociation       = "attachment_association_prerequisite"
	FamilyDrift             = "state_drift"
	FamilyOrderingVisible   = "ordering_terraform_visible"
	FamilyOrderingInvisible = "ordering_terraform_invisible"
	FamilyTransient         = "transient_eventual_consistency"
)

// The rule schema is defined in the rules package and re-exported here.
const (
	TrustGenerated       = rules.TrustGenerated
	TrustProviderRuntime = rules.TrustProviderRuntime
	TrustAWSModel        = rules.TrustAWSModel
	TrustVerified        = rules.TrustVerified

	IdentityServerGenerated = rules.IdentityServerGenerated
	IdentityUnknown         = rules.IdentityUnknown

	KeyID   = rules.KeyID
	KeyARN  = rules.KeyARN
	KeyName = rules.KeyName

	NormalizationNone           = rules.NormalizationNone
	NormalizationARNComponent   = rules.NormalizationARNComponent
	NormalizationARNLastSegment = rules.NormalizationARNLastSegment
)

type (
	// Lookup is how to ask AWS whether a target exists; see [rules.Lookup].
	Lookup = rules.Lookup
	// ExistenceRule is one reference that must name an existing target; see
	// [rules.ExistenceRule].
	ExistenceRule = rules.ExistenceRule
	// ReferenceKey is how a planned value maps to a lookup identifier; see
	// [rules.ReferenceKey].
	ReferenceKey = rules.ReferenceKey
	// EnforcementFingerprint identifies the semantics evidence was gathered
	// against; see [rules.EnforcementFingerprint].
	EnforcementFingerprint = rules.EnforcementFingerprint
)

// Existence is what an inspection concluded about one identifier.
type Existence string

// Answers an inspection can reach. Only Exists and NotFound are definite.
const (
	Exists   Existence = "exists"
	NotFound Existence = "not_found"
	// Unknown is every other answer, such as AccessDenied, throttling, an
	// unsupported lookup, or a response that did not clearly say. It is never
	// read as absence.
	Unknown Existence = "unknown"
)

// Verdicts the engine reaches for one rule.
const (
	VerdictSatisfied       = "satisfied"
	VerdictSatisfiedByPlan = "satisfied_by_plan"
	VerdictViolation       = "violation"
	VerdictPartial         = "partial"
	VerdictOrderingRisk    = "ordering_risk"
	VerdictNotApplicable   = "not_applicable"
)

// Result is one rule applied to one planned change.
type Result struct {
	Address string
	Family  string
	Verdict string
	Reason  string
	Finding *model.Finding
}

// Coverage states for a planned resource.
const (
	CoverageChecked      = "checked"
	CoveragePartial      = "partial"
	CoverageNoRule       = "no_dependency_rule_discovered"
	CoverageUnsupported  = "unsupported"
	CoverageNotRequested = "no_dependency_relevant_action"
)
