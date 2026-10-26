package counters

import (
	"context"
	"errors"
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/checks/quotas"
)

type fakeCounter struct {
	name  string
	value quotas.Measurement
}

func (f fakeCounter) Adapter() string { return f.name }

func (f fakeCounter) Count(context.Context, quotas.UsageContext) quotas.Measurement { return f.value }

func TestRegistryPreservesKnownZeroAndUnknownFailure(t *testing.T) {
	registry := NewRegistry()
	registry.Register(fakeCounter{name: "test:zero", value: quotas.Known(0)})
	registry.Register(fakeCounter{name: "test:failure", value: quotas.Unknown(errors.New("AccessDenied").Error())})
	if got := registry.Count(context.Background(), &quotas.UsageCounter{Adapter: "test:zero"}, quotas.UsageContext{}); !got.Known || got.Value != 0 {
		t.Fatalf("successful empty result = %+v, want known zero", got)
	}
	if got := registry.Count(context.Background(), &quotas.UsageCounter{Adapter: "test:failure"}, quotas.UsageContext{}); got.Known {
		t.Fatalf("failed API result = %+v, want unknown", got)
	}
	if got := registry.Count(context.Background(), &quotas.UsageCounter{Adapter: "missing"}, quotas.UsageContext{}); got.Known {
		t.Fatalf("missing generated adapter = %+v, want unknown", got)
	}
}
