package model

// CheckStatus is how completely a check evaluated a resource.
type CheckStatus string

// Statuses a check can report for a resource.
const (
	CheckChecked CheckStatus = "checked"
	// CheckPartialUnresolvedAuthorization means a required API operation has no
	// known IAM action, so it was never checked.
	CheckPartialUnresolvedAuthorization CheckStatus = "partial-unresolved-authorization"
	// CheckPartialUnevaluableCondition means an operation may run during apply
	// but the plan does not say whether its code path is taken, so its
	// permission can neither be checked nor discarded.
	CheckPartialUnevaluableCondition CheckStatus = "partial-unevaluable-condition"
	CheckSkipped                     CheckStatus = "skipped"
	CheckUnsupported                 CheckStatus = "unsupported"
	CheckUnverifiable                CheckStatus = "unverifiable"
	CheckNotApplicable               CheckStatus = "not-applicable"
	CheckPartialDependency           CheckStatus = "partial-dependency"
	// CheckPartialAWSContext means the check needs AWS but the account or region
	// Terraform applies to is unknown, so it did not look: asking somewhere else
	// answers a different question.
	CheckPartialAWSContext CheckStatus = "partial-aws-context"
	// CheckPartialSimulationUnavailable means IAM could not simulate the apply
	// identity's permissions (denied, throttled, unreachable).
	CheckPartialSimulationUnavailable CheckStatus = "partial-simulation-unavailable"
	CheckNoDependencyRule             CheckStatus = "no-additional-rule-discovered"
	// CheckNoQuotaRule means tfpreflight knows no quota for the resource type,
	// so the quota check had nothing to check.
	CheckNoQuotaRule CheckStatus = "no-quota-rule"
)

// ResourceCoverage is the AWS checks considered for one resource.
type ResourceCoverage struct {
	Resource     string
	Trust        string
	Permissions  CheckStatus
	Conflicts    CheckStatus
	Quota        CheckStatus
	Dependencies CheckStatus
	// UnresolvedAuthorizationOperations are required API operations whose IAM
	// authorization is unknown.
	UnresolvedAuthorizationOperations []string
	// UnevaluableConditionOperations are operations that may run during apply
	// under a condition the plan cannot decide. Listing them stops an unverified
	// path from reading as a clean result.
	UnevaluableConditionOperations []string
	// UnresolvedAWSContext is why the AWS account or region is unknown. When
	// set, every check that needs AWS is partial.
	UnresolvedAWSContext string
	// PermissionsUnavailable says why permissions were not simulated.
	PermissionsUnavailable string
}

// IsPartial reports whether a check completed only in part. The kinds of partial
// read alike to a person; they are kept apart so the reason survives in JSON.
func (s CheckStatus) IsPartial() bool {
	return s == CheckPartialUnresolvedAuthorization || s == CheckPartialUnevaluableCondition || s == CheckPartialDependency || s == CheckPartialAWSContext || s == CheckPartialSimulationUnavailable
}

// PartialReasons lists every operation a resource's permission result does not
// cover.
func (r ResourceCoverage) PartialReasons() []string {
	return append(append([]string(nil), r.UnresolvedAuthorizationOperations...), r.UnevaluableConditionOperations...)
}

// Coverage is the AWS check coverage of one plan.
type Coverage struct {
	// ProviderVersion is the exact version Terraform selected, and
	// ProviderKnowledge whether tfpreflight ships knowledge for it. Knowledge is
	// never borrowed from another version, so an unsupported version means the
	// checks did not run, not that they passed.
	ProviderVersion   string
	ProviderKnowledge CheckStatus
	// AWSAnswers counts the permission simulations and dependency lookups AWS
	// answered, and AWSFailures says why dependency lookups got none. Their
	// statuses cannot say: a dependency check can pass on the plan alone, and
	// a permission IAM answered can still be partial.
	AWSAnswers  int
	AWSFailures []string
	Resources   []ResourceCoverage
}

// AWSContext tells the credentials inspecting AWS apart from the identity
// expected to run terraform apply.
type AWSContext struct {
	InspectionIdentity string
	ApplyIdentity      string
	ApplyIdentityKnown bool
	// ApplyIdentitySource is where the apply identity came from: --principal,
	// the provider's assume_role, or the inspection identity. ApplyIdentityNote
	// says why it is unknown, or anything else to know about it.
	ApplyIdentitySource string
	ApplyIdentityNote   string
	// AssumedRole is the provider's role the inspection checks assumed, and
	// InspectionUnavailable why they could not.
	AssumedRole           string
	InspectionUnavailable string
	// Region is the one region every AWS check inspected, and RegionSource where
	// it came from: "provider block", "var.<name>" or "environment".
	Region       string
	RegionSource string
	// Unresolved is why the account or region could not be decided; when set, no
	// AWS check ran.
	Unresolved string
}
