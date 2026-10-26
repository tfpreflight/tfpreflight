package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/tfpreflight/tfpreflight/internal/checks/dependencies"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/tfpreflight/tfpreflight/internal/checks/dependencies/adapters"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// DependencyRuntime runs the dependency check with an inspection identity rather
// than a run context, for tests and tools. Without the provider block's source
// it cannot confirm a variable region; a run resolves its scope once and calls
// dependencyRuntime.
func DependencyRuntime(ctx context.Context, data []byte, version string, config sdk.Config, inspectionIdentity string, resolver dependencies.ExistenceResolver) ([]dependencies.Result, map[string]string, error) {
	plan, err := dependencies.ParsePlan(data)
	if err != nil {
		return nil, nil, err
	}
	decided := resolveScope(scopeInputs{Provider: plan.DefaultContext, InspectionIdentity: inspectionIdentity, Profile: inspectionProfile(), EnvironmentRegion: config.Region})
	outcome, err := dependencyRuntime(ctx, plan, version, config, decided, resolver)
	return outcome.Results, outcome.Coverage, err
}

// dependencyOutcome is what the dependency check found, and how its AWS
// lookups went: Answered lookups, and why the Failures got no answer.
type dependencyOutcome struct {
	Results  []dependencies.Result
	Coverage map[string]string
	Answered int
	Failures []string
	// EvidenceProblems are claims in the shipped enforcement evidence that did
	// not load. Each is dropped, so it never blocks; the run's diagnostics say
	// so.
	EvidenceProblems []string
}

func dependencyRuntime(ctx context.Context, plan dependencies.Plan, version string, config sdk.Config, decided scope, resolver dependencies.ExistenceResolver) (dependencyOutcome, error) {
	rules, err := adapters.Rules(version)
	if err != nil {
		coverage := map[string]string{}
		for address := range plan.Changes {
			coverage[address] = dependencies.CoverageUnsupported
		}
		return dependencyOutcome{Coverage: coverage}, nil
	}
	config.Region = decided.Region
	var registry *adapters.Registry
	if resolver == nil {
		registry = adapters.New(version, config)
		resolver = registry
	}
	resolver = &dependencyScopeResolver{next: resolver, reason: decided.Reason, region: decided.Region, account: decided.Account, partition: decided.Partition}
	// Enforcement evidence ships with the binary; loading it makes no AWS call.
	enforcement, problems := dependencies.EnforcementFor(version)
	evidenceProblems := make([]string, 0, len(problems))
	for _, problem := range problems {
		evidenceProblems = append(evidenceProblems, "dependency enforcement evidence for "+version+": "+problem)
	}
	engine := dependencies.Engine{
		Existence: rules, Resolver: resolver,
		Scope:           dependencies.Scope{Region: decided.Region, Account: decided.Account},
		Enforcement:     enforcement,
		ProviderVersion: version,
	}
	outcome := dependencyOutcome{EvidenceProblems: evidenceProblems}
	outcome.Results, outcome.Coverage = engine.Evaluate(ctx, plan)
	if registry != nil {
		outcome.Answered, outcome.Failures = registry.Lookups()
	}
	return outcome, nil
}

type dependencyScopeResolver struct {
	next                               dependencies.ExistenceResolver
	reason, region, account, partition string
}

// Exists resolves a dependency identity in the requested AWS scope.
func (r *dependencyScopeResolver) Exists(ctx context.Context, l dependencies.Lookup, scope dependencies.Scope, id string) (dependencies.Existence, string) {
	if refusal := r.refuse(id); refusal != "" {
		return dependencies.Unknown, refusal
	}
	return r.next.Exists(ctx, l, scope, id)
}

// Prefetch applies the same refusals before scheduling anything, so a lookup
// that would be refused is never sent concurrently either.
func (r *dependencyScopeResolver) Prefetch(ctx context.Context, requests []dependencies.LookupRequest) {
	prefetcher, ok := r.next.(dependencies.Prefetcher)
	if !ok {
		return
	}
	allowed := make([]dependencies.LookupRequest, 0, len(requests))
	for _, request := range requests {
		if r.refuse(request.Identifier) == "" {
			allowed = append(allowed, request)
		}
	}
	prefetcher.Prefetch(ctx, allowed)
}

// refuse says why a lookup must not be sent, or "".
func (r *dependencyScopeResolver) refuse(id string) string {
	if r.reason != "" {
		return r.reason
	}
	if !strings.HasPrefix(id, "arn:") {
		return ""
	}
	target, err := arn.Parse(id)
	if err != nil {
		return "malformed dependency ARN"
	}
	if target.AccountID != "" && target.AccountID != r.account {
		return "dependency ARN belongs to another account"
	}
	if target.Partition != r.partition {
		return "dependency ARN belongs to another partition"
	}
	if target.Region != "" && target.Region != r.region {
		return "dependency ARN belongs to another region"
	}
	return ""
}

func applyDependencyRuntime(ctx context.Context, checked *Result, data []byte, version string, config sdk.Config) {
	results, coverage, err := DependencyRuntime(ctx, data, version, config, checked.Context.InspectionIdentity, nil)
	applyDependencyResults(checked, dependencyOutcome{Results: results, Coverage: coverage}, err)
}

func applyDependencyResults(checked *Result, outcome dependencyOutcome, err error) {
	results, coverage := outcome.Results, outcome.Coverage
	checked.Coverage.AWSAnswers += outcome.Answered
	checked.Coverage.AWSFailures = append(checked.Coverage.AWSFailures, outcome.Failures...)
	checked.Debug = append(checked.Debug, outcome.EvidenceProblems...)
	if err != nil {
		checked.Debug = append(checked.Debug, "Dependency plan parsing unavailable")
		for i := range checked.Coverage.Resources {
			checked.Coverage.Resources[i].Dependencies = model.CheckPartialDependency
		}
		return
	}
	for _, r := range results {
		if r.Finding != nil {
			checked.Findings = append(checked.Findings, *r.Finding)
		}
		checked.Debug = append(checked.Debug, fmt.Sprintf("%s: dependency %s: %s", r.Address, r.Verdict, r.Reason))
	}
	for i := range checked.Coverage.Resources {
		resource := &checked.Coverage.Resources[i]
		switch coverage[resource.Resource] {
		case dependencies.CoverageChecked:
			resource.Dependencies = model.CheckChecked
		case dependencies.CoveragePartial:
			resource.Dependencies = model.CheckPartialDependency
		case dependencies.CoverageUnsupported:
			resource.Dependencies = model.CheckUnsupported
		case dependencies.CoverageNotRequested:
			resource.Dependencies = model.CheckNotApplicable
		default:
			resource.Dependencies = model.CheckNoDependencyRule
		}
	}
}
