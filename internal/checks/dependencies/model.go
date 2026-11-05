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
	// Malformed is AWS saying the identifier is not a valid ID, so no object
	// can have it. It is not a not-found answer, and it never blocks.
	Malformed Existence = "malformed"
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

// Why a partial result could not be decided, when the engine knows. An empty
// cause means the plan did not hold enough to decide.
const (
	// CauseNoLookup means this tfpreflight has no code to run the rule's
	// lookup.
	CauseNoLookup = "no_lookup"
	// CauseNoAnswer means the lookup ran or was tried, and got no answer that
	// proves the target present or absent.
	CauseNoAnswer = "no_answer"
)

// Reasons a resolver gives when this tfpreflight cannot run a rule's lookup at
// all. They are not about AWS's answer, so a newer tfpreflight may run the
// rule.
const (
	// ReasonLookupNotApproved is the reason when the rule's lookup meaning is
	// not one this tfpreflight knows.
	ReasonLookupNotApproved = "unregistered identifier or lookup semantics"
	// ReasonNoLookupCode starts the reason when no code serves the lookup; the
	// lookup's name follows.
	ReasonNoLookupCode = "typed lookup adapter unavailable: "
)

// Result is one rule applied to one planned change.
type Result struct {
	Address string
	Family  string
	// Attribute is the configuration argument the rule is about, when the
	// rule has one.
	Attribute string
	Verdict   string
	Reason    string
	// Cause is why a partial result could not be decided; see CauseNoLookup.
	Cause   string
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
