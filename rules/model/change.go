// Package model holds the planned-change, finding, coverage and provider types
// the checks share.
package model

// Action describes the intended change to a resource.
type Action string

// Actions a planned change can take.
const (
	ActionCreate  Action = "create"
	ActionUpdate  Action = "update"
	ActionDelete  Action = "delete"
	ActionReplace Action = "replace"
	ActionNoOp    Action = "no-op"
)

// PlannedChange is the part of a Terraform plan tfpreflight reads.
type PlannedChange struct {
	Address      string
	ResourceType string
	ProviderName string
	// ProviderConfigKey is the provider configuration Terraform resolved for
	// the resource: "aws" for the root module's default AWS provider,
	// "aws.west" for an alias, including one a module received, and
	// "module.x:aws" for a module's own provider block. It is "" when the
	// plan does not say.
	ProviderConfigKey string
	Action            Action
	Before            any
	After             any
	AfterUnknown      any
}

// DefaultAWSProviderKey is the configuration key of the root module's
// default AWS provider, the one whose account and region a run inspects.
const DefaultAWSProviderKey = "aws"

// AliasedProviderReason is why a check that needs AWS did not look at a
// resource on any other provider configuration.
const AliasedProviderReason = "aliased provider; region not reconstructed"

// OnDefaultAWSProvider reports whether the change is known to use the default
// AWS provider configuration. A change whose configuration is unknown is not.
func (c PlannedChange) OnDefaultAWSProvider() bool {
	return c.ProviderConfigKey == DefaultAWSProviderKey
}
