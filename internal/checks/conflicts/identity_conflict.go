package conflicts

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// loadConflictRules reads the conflict rules for a provider version. A version
// with none is a supported partial-coverage state.
func loadConflictRules(providerVersion string) ([]Rule, error) {
	// Verified rules are curated; generated rules come from the pack build. A
	// verified rule wins over a generated one for the same type.
	var rules []Rule
	seen := map[string]bool{}
	for _, name := range []string{"aws/conflict/aws-" + providerVersion + ".json", "aws/conflict/generated-aws-" + providerVersion + ".json"} {
		data, err := packs.ReadFile(name)
		if err != nil {
			continue
		}
		var file RuleFile
		if err := json.Unmarshal(data, &file); err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		if file.ProviderVersion != providerVersion {
			return nil, fmt.Errorf("%s is for provider %s, not %s", name, file.ProviderVersion, providerVersion)
		}
		for _, entry := range file.Rules {
			if seen[entry.ResourceType] {
				continue
			}
			seen[entry.ResourceType] = true
			rules = append(rules, entry.Rule)
		}
	}
	return rules, nil
}

// PredictIdentityConflicts checks planned creates against resources AWS already
// has, in the run's AWS context.
func PredictIdentityConflicts(ctx context.Context, config awssdk.Config, providerVersion string, changes []model.PlannedChange) ([]model.Finding, []Coverage, error) {
	rules, err := loadConflictRules(providerVersion)
	if err != nil {
		return nil, nil, err
	}
	if len(rules) == 0 {
		return nil, nil, nil
	}
	// The generic engine answers every lookup with a spec; SDK adapters answer
	// the rest, including the hand-written SageMaker one, whose absence is a
	// message.
	registry := NewRegistry()
	if err := registerEngine(registry, config, providerVersion); err != nil {
		return nil, nil, err
	}
	RegisterGenerated(registry, config)
	registry.Register(SageMakerModelPackageGroups{Client: sagemaker.NewFromConfig(config)})
	findings, coverage := NewResolver(rules, registry).Check(ctx, changes)
	return findings, coverage, nil
}

// UnresolvedContextCoverage is the resolver's coverage when the run's AWS
// context is unresolved: every check it would have made says so, and nothing is
// sent.
func UnresolvedContextCoverage(providerVersion string, changes []model.PlannedChange) ([]Coverage, error) {
	rules, err := loadConflictRules(providerVersion)
	if err != nil {
		return nil, err
	}
	_, coverage := NewResolver(rules, nil).Check(context.Background(), changes)
	return coverage, nil
}
