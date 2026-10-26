package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/tfpreflight/tfpreflight/internal/awscall"
	"github.com/tfpreflight/tfpreflight/internal/checks/dependencies"
	"github.com/tfpreflight/tfpreflight/internal/packs"
)

// Specs reads the lookup spec pack for version from the active pack set,
// parsing each set's copy once.
func Specs(version string) (awscall.SpecSet, error) {
	packs, err := packs.Active()
	if err != nil {
		return awscall.SpecSet{}, err
	}
	key := specsKey{packs, version}
	specsMu.Lock()
	defer specsMu.Unlock()
	if set, ok := specsCache[key]; ok {
		return set, nil
	}
	data, err := packs.ReadFile("aws/lookup/specs-" + version + ".json")
	if err != nil {
		return awscall.SpecSet{}, err
	}
	var set awscall.SpecSet
	if err := json.Unmarshal(data, &set); err != nil {
		return awscall.SpecSet{}, fmt.Errorf("lookup spec pack: %w", err)
	}
	if err := set.Check(); err != nil {
		return awscall.SpecSet{}, fmt.Errorf("lookup spec pack: %w", err)
	}
	specsCache[key] = set
	return set, nil
}

type specsKey struct {
	packs   *packs.Set
	version string
}

var (
	specsMu    sync.Mutex
	specsCache = map[specsKey]awscall.SpecSet{}
)

// engineLookups answers every lookup with a spec through the generic engine.
// A spec must say exactly what its rules say proves absence; a pack where
// they disagree is unusable.
func engineLookups(version string, config aws.Config, rules []dependencies.ExistenceRule) (map[string]lookupFunc, error) {
	set, err := Specs(version)
	if err != nil {
		return nil, err
	}
	specs := map[string]awscall.Spec{}
	for _, spec := range set.Specs {
		specs[spec.Service+"/"+spec.Operation+"/"+spec.Field] = spec
	}
	for _, rule := range rules {
		spec, ok := specs[lookupKey(rule.Lookup)]
		if !ok {
			continue
		}
		codes := slices.Clone(rule.Lookup.NotFoundCodes)
		sort.Strings(codes)
		if !slices.Equal(codes, spec.NotFound.Codes) || rule.Lookup.NotFoundType != spec.NotFound.Type {
			return nil, fmt.Errorf("lookup spec %s disagrees with its dependency rules about what proves absence", lookupKey(rule.Lookup))
		}
	}
	engine := awscall.New(config, set.Partitions)
	lookups := map[string]lookupFunc{}
	for key, spec := range specs {
		// The engine does not discover endpoints; where the configuration
		// turns discovery on, the lookup belongs to its SDK client.
		if engine.Discovers(spec) {
			continue
		}
		lookups[key] = func(ctx context.Context, _ dependencies.Lookup, scope dependencies.Scope, id string) (dependencies.Existence, string) {
			state, reason := engine.Lookup(ctx, spec, scope.Region, id)
			switch state {
			case awscall.Exists:
				return dependencies.Exists, reason
			case awscall.NotFound:
				return dependencies.NotFound, reason
			}
			return dependencies.Unknown, reason
		}
	}
	return lookups, nil
}
