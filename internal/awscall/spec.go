// Package awscall is the generic AWS engine: it answers existence lookups
// described by data, with SigV4 signing and net/http, and no service SDK
// clients. Everything specific to a service is in a Spec from the lookup packs;
// the engine knows the AWS wire protocols and nothing about any service.
package awscall

import "github.com/tfpreflight/tfpreflight/rules"

// The lookup spec format is defined in the rules package; the checks that hand
// specs to an Engine name them here.
type (
	// Spec describes one existence lookup; see [rules.Spec].
	Spec = rules.Spec
	// SpecSet is a lookup spec pack; see [rules.SpecSet].
	SpecSet = rules.SpecSet
)
