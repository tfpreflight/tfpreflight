// Package counters holds generated AWS SDK usage counters. A counter reports a
// known count or an unknown measurement; every quota decision stays in
// internal/checks/quotas.
package counters

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/tfpreflight/tfpreflight/internal/checks/quotas"
)

// Counter is one generated usage count.
type Counter interface {
	Adapter() string
	Count(context.Context, quotas.UsageContext) quotas.Measurement
}

// Registry finds a generated counter by its adapter name.
type Registry struct{ byAdapter map[string]Counter }

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{byAdapter: map[string]Counter{}} }

// Register adds counters by adapter name, skipping a nil or unnamed one; a later
// counter with the same name replaces an earlier one.
func (r *Registry) Register(counters ...Counter) {
	for _, counter := range counters {
		if counter != nil && counter.Adapter() != "" {
			r.byAdapter[counter.Adapter()] = counter
		}
	}
}

// Has reports whether a counter is registered for adapter. A rule whose adapter
// is missing is a partial check, never zero usage.
func (r *Registry) Has(adapter string) bool {
	_, found := r.byAdapter[adapter]
	return found
}

// Count runs the counter spec names. Missing metadata or a counter that is not
// registered is an unknown measurement, never zero.
func (r *Registry) Count(ctx context.Context, spec *quotas.UsageCounter, input quotas.UsageContext) quotas.Measurement {
	if spec == nil || spec.Adapter == "" {
		return quotas.Unknown("generated quota counter metadata is missing its adapter")
	}
	counter, found := r.byAdapter[spec.Adapter]
	if !found {
		return quotas.Unknown(fmt.Sprintf("generated quota counter %q is not loaded", spec.Adapter))
	}
	return counter.Count(ctx, input)
}

// RegisterGenerated registers every generated counter, with no reflection or
// call-by-name SDK mechanism.
func RegisterGenerated(registry *Registry, config aws.Config) {
	registerGeneratedCounters(registry, config)
}
