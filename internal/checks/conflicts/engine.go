package conflicts

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/tfpreflight/tfpreflight/internal/awscall"
	"github.com/tfpreflight/tfpreflight/internal/packs"
)

func conflictSpecs(providerVersion string) (awscall.SpecSet, error) {
	data, err := packs.ReadFile("aws/lookup/conflict-specs-" + providerVersion + ".json")
	if err != nil {
		return awscall.SpecSet{}, err
	}
	var set awscall.SpecSet
	if err := json.Unmarshal(data, &set); err != nil {
		return awscall.SpecSet{}, fmt.Errorf("conflict lookup spec pack: %w", err)
	}
	if err := set.Check(); err != nil {
		return awscall.SpecSet{}, fmt.Errorf("conflict lookup spec pack: %w", err)
	}
	return set, nil
}

// registerEngine adds an engine-backed adapter for every conflict lookup with a
// spec, before the SDK adapters, so they answer. The SDK adapters remain for
// lookups without a spec, and those whose endpoint the SDK would discover.
func registerEngine(registry *Registry, config awssdk.Config, providerVersion string) error {
	set, err := conflictSpecs(providerVersion)
	if err != nil {
		return err
	}
	engine := awscall.New(config, set.Partitions)
	for _, spec := range set.Specs {
		if engine.Discovers(spec) {
			continue
		}
		registry.Register(engineAdapter{engine: engine, spec: spec})
	}
	return nil
}

type engineAdapter struct {
	engine *awscall.Engine
	spec   awscall.Spec
}

// Service returns the AWS service named by the lookup specification.
func (a engineAdapter) Service() string { return a.spec.Service }

// Supports reports whether operation is this adapter's operation.
func (a engineAdapter) Supports(operation string) bool { return operation == a.spec.Operation }

// Lookup asks the generic AWS call engine to resolve the requested identity.
func (a engineAdapter) Lookup(ctx context.Context, request LookupRequest) (Outcome, error) {
	// A single identity is the lookup's one input; a composite one fills each
	// input member.
	values := map[string]string{}
	if len(a.spec.Inputs) == 1 {
		values[a.spec.Inputs[0].Member] = request.Identity
	} else {
		for _, input := range a.spec.Inputs {
			values[input.Member] = request.Values[input.Member]
		}
	}
	answer := a.engine.Inspect(ctx, a.spec, "", values)
	switch answer.Result {
	case awscall.Exists:
		return OutcomeExists, nil
	case awscall.NotFound:
		return OutcomeNotFound, nil
	}
	if answer.Failure == nil {
		return OutcomeUnknown, nil
	}
	return OutcomeUnknown, answer.Failure
}

// EngineAdapter is the engine-backed adapter for one conflict spec, for tools
// that compare it with the SDK adapters.
func EngineAdapter(engine *awscall.Engine, spec awscall.Spec) LookupAdapter {
	return engineAdapter{engine: engine, spec: spec}
}
