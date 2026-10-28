// Package aws runs the checks that call AWS. It decides the run's account,
// region and credentials once and gives them to every check, so no check decides
// them for itself.
package aws

import (
	"context"
	"fmt"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/tfpreflight/tfpreflight/internal/checks/conflicts"
	"github.com/tfpreflight/tfpreflight/internal/checks/dependencies"
	"github.com/tfpreflight/tfpreflight/internal/checks/permissions"
	"github.com/tfpreflight/tfpreflight/internal/checks/quotas"
	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// Result is the combined result of the AWS checks.
type Result struct {
	Findings model.Findings
	Context  model.AWSContext
	Coverage model.Coverage
	Debug    []string
}

// Run runs the AWS checks for the planned changes.
func Run(ctx context.Context, changes []model.PlannedChange, principal, providerVersion string, planJSON []byte) (Result, error) {
	if !containsAWSChanges(changes) {
		return Result{}, nil
	}
	run := resolveRunContext(ctx, productionContextSources(), planJSON, principal)
	return runChecks(ctx, productionChecks(), run, changes, providerVersion, planJSON)
}

// awsChecks are the checks that call AWS, replaceable in tests.
type awsChecks struct {
	Conflicts         func(context.Context, RunContext, []packs.ResolvedRule) ([]model.Finding, error)
	IdentityConflicts func(context.Context, RunContext, string, []model.PlannedChange) ([]model.Finding, []conflicts.Coverage, error)
	EC2VCPU           func(context.Context, RunContext, []packs.ResolvedRule) ([]model.Finding, error)
	Quotas            func(context.Context, RunContext, []model.PlannedChange, map[string]quotas.Rule) []model.Finding
	Permissions       func(context.Context, RunContext, []packs.ResolvedRule) permissions.Result
	Dependencies      func(context.Context, RunContext, []byte, string) (dependencyOutcome, error)
}

func productionChecks() awsChecks {
	return awsChecks{
		Conflicts: func(ctx context.Context, run RunContext, rules []packs.ResolvedRule) ([]model.Finding, error) {
			return PredictConflicts(ctx, run.Config, rules)
		},
		IdentityConflicts: func(ctx context.Context, run RunContext, version string, changes []model.PlannedChange) ([]model.Finding, []conflicts.Coverage, error) {
			return conflicts.PredictIdentityConflicts(ctx, run.Config, version, changes)
		},
		EC2VCPU: func(ctx context.Context, run RunContext, rules []packs.ResolvedRule) ([]model.Finding, error) {
			return quotas.PredictEC2VCPUQuota(ctx, run.Config, rules)
		},
		Quotas: func(ctx context.Context, run RunContext, changes []model.PlannedChange, rules map[string]quotas.Rule) []model.Finding {
			inspector := NewAWSQuotaInspector(run.Config)
			resolver := ec2VCPUResolver{client: ec2.NewFromConfig(run.Config), ctx: ctx}
			return quotas.PredictQuotas(ctx, changes, rules, inspector, resolver)
		},
		Permissions: func(ctx context.Context, run RunContext, rules []packs.ResolvedRule) permissions.Result {
			return permissions.PredictPermissions(ctx, run.Config, run.Identity.ApplyIdentity, run.permissionScope(), rules)
		},
		Dependencies: func(ctx context.Context, run RunContext, data []byte, version string) (dependencyOutcome, error) {
			parsed, err := dependencies.ParsePlan(data)
			if err != nil {
				return dependencyOutcome{}, err
			}
			scope := run.scope()
			if scope.Reason == "" {
				scope.Reason = run.InspectionUnavailable
			}
			return dependencyRuntime(ctx, parsed, version, run.Config, scope, nil)
		},
	}
}

// runChecks runs every check against one run context. When the context is
// unresolved no check calls AWS: each one that applies is partial, and only what
// needs no AWS call still runs.
func runChecks(ctx context.Context, checks awsChecks, run RunContext, changes []model.PlannedChange, providerVersion string, plan []byte) (Result, error) {
	pack, generatedLoaded, packErr := packs.LoadRuntimePack(providerVersion)
	if packErr != nil {
		return Result{}, packErr
	}
	rules := packs.ResolveRules(pack, changes)
	// Only the default provider configuration's account and region are
	// inspected. A resource on any other configuration is left out of the checks
	// that call AWS and reported partial, so nothing about it is answered from
	// the wrong place.
	inspected, inspectedRules, aliased := defaultProviderOnly(changes, rules)
	// A quota that cannot be read is an unknown measurement, which makes the
	// result partial rather than failing the run.
	quotaRules, quotaRulesLoaded, quotaErr := quotas.LoadQuotaRules(providerVersion)
	if quotaErr != nil {
		return Result{}, quotaErr
	}

	var findings []model.Finding
	var resolverCoverage []conflicts.Coverage
	if run.Inspects() {
		inspectionFindings, identityCoverage, err := runInspectionChecks(ctx, checks, run, inspected, providerVersion, inspectedRules, quotaRules, quotaRulesLoaded)
		if err != nil {
			return Result{}, err
		}
		findings, resolverCoverage = inspectionFindings, identityCoverage
	}
	permissionFindings, permissionsUnchecked, permissionAnswers := runPermissionChecks(ctx, checks, run, inspectedRules)
	findings = append(findings, permissionFindings...)
	// Reported whether or not the apply identity is known: an operation with no
	// IAM mapping cannot be verified either way, and silence would read as a
	// pass.
	findings = append(findings, permissions.PredictUnresolvedAuthorization(changes, rules)...)
	if !generatedLoaded {
		findings = append(findings, unsupportedProviderFinding(providerVersion))
	}
	debug := debugLines(run, providerVersion, generatedLoaded, rules)
	coverage := buildCoverage(changes, rules, run.Identity, findings, generatedLoaded)
	coverage.ProviderVersion = providerVersion
	coverage.AWSAnswers = permissionAnswers
	quotas.ApplyQuotaCoverage(&coverage, changes, quotaRules, quotaRulesLoaded, findings)
	unsent, err := unsentLookups(run, providerVersion, changes, aliased)
	if err != nil {
		return Result{}, err
	}
	applyResolverCoverage(&coverage, append(resolverCoverage, unsent...))
	applyUncheckedPermissions(&coverage, permissionsUnchecked)
	markRunContext(&coverage, run)
	markAliased(&coverage, aliased)
	checked := Result{Findings: findings, Context: run.Identity, Coverage: coverage, Debug: debug}
	if plan != nil {
		// The dependency check runs either way: its lookups refuse an unresolved
		// context, while a dependency the plan itself satisfies needs no AWS
		// call.
		outcome, err := checks.Dependencies(ctx, run, plan, providerVersion)
		applyDependencyResults(&checked, outcome, err)
	}
	appendRawAWSDiagnostics(&checked)
	return checked, nil
}

// appendRawAWSDiagnostics keeps provider error details out of normal output.
// The CLI shows diagnostics only when the user passes --debug.
func appendRawAWSDiagnostics(checked *Result) {
	for _, finding := range checked.Findings {
		if finding.AWSError != "" {
			checked.Debug = append(checked.Debug, "AWS error: "+finding.AWSError)
		}
	}
	for _, failure := range checked.Coverage.AWSFailures {
		checked.Debug = append(checked.Debug, "AWS error: "+failure)
	}
	if checked.Context.InspectionUnavailable != "" {
		checked.Debug = append(checked.Debug, "AWS inspection error: "+checked.Context.InspectionUnavailable)
	}
}

// unsentLookups is the resolver's coverage for lookups it did not send: all of
// them when the run's context is unresolved, and an aliased resource's always.
func unsentLookups(run RunContext, providerVersion string, changes, aliased []model.PlannedChange) ([]conflicts.Coverage, error) {
	notSent := aliased
	if !run.Inspects() {
		notSent = changes
	}
	if len(notSent) == 0 {
		return nil, nil
	}
	return conflicts.UnresolvedContextCoverage(providerVersion, notSent)
}

// runInspectionChecks runs the checks that inspect the account: name and
// identity conflicts, the EC2 vCPU quota, and generated quota rules.
func runInspectionChecks(ctx context.Context, checks awsChecks, run RunContext, changes []model.PlannedChange, providerVersion string, rules []packs.ResolvedRule, quotaRules map[string]quotas.Rule, quotaRulesLoaded bool) ([]model.Finding, []conflicts.Coverage, error) {
	nameConflicts, err := checks.Conflicts(ctx, run, rules)
	if err != nil {
		return nil, nil, err
	}
	findings := append([]model.Finding(nil), nameConflicts...)
	identityConflicts, identityCoverage, err := checks.IdentityConflicts(ctx, run, providerVersion, changes)
	if err != nil {
		return nil, nil, err
	}
	findings = append(findings, identityConflicts...)
	vcpuFindings, err := checks.EC2VCPU(ctx, run, rules)
	if err != nil {
		return nil, nil, err
	}
	findings = append(findings, vcpuFindings...)
	if quotaRulesLoaded {
		findings = append(findings, checks.Quotas(ctx, run, changes, quotaRules)...)
	}
	return findings, identityCoverage, nil
}

// runPermissionChecks simulates the apply identity's permissions when the run
// knows who applies. A simulation that cannot run leaves permissions partial; it
// never fails the run.
func runPermissionChecks(ctx context.Context, checks awsChecks, run RunContext, rules []packs.ResolvedRule) ([]model.Finding, permissions.Unchecked, int) {
	if !run.Resolved() || !run.Identity.ApplyIdentityKnown {
		return nil, nil, 0
	}
	outcome := checks.Permissions(ctx, run, rules)
	findings := append([]model.Finding(nil), outcome.Findings...)
	findings = append(findings, permissions.UncheckedFindings(outcome.Unchecked)...)
	findings = append(findings, permissions.PartialFindings(outcome.Partial)...)
	unchecked := permissions.Unchecked{}
	for address, reason := range outcome.Partial {
		unchecked[address] = reason
	}
	for address, reason := range outcome.Unchecked {
		unchecked[address] = reason
	}
	return findings, unchecked, outcome.Answered
}

func debugLines(run RunContext, providerVersion string, generatedLoaded bool, rules []packs.ResolvedRule) []string {
	debug := []string{fmt.Sprintf("AWS provider version: %s", providerVersion), fmt.Sprintf("Rules for this provider version loaded: %t", generatedLoaded)}
	if run.Resolved() {
		debug = append(debug, fmt.Sprintf("AWS context: account %s, region %s (from %s)", run.Account, run.Region, run.RegionSource))
		if run.Profile != "" {
			debug = append(debug, fmt.Sprintf("AWS profile: %s (from %s)", run.Profile, run.ProfileSource))
		}
	} else {
		debug = append(debug, "AWS context unresolved: "+run.Unresolved)
	}
	if run.CredentialsError != "" {
		debug = append(debug, "AWS credentials: "+run.CredentialsError)
	}
	for _, rule := range rules {
		for _, operation := range rule.Action.Operations {
			debug = append(debug, fmt.Sprintf("%s: trust=%s action=%s operation=%s permission=%s certainty=%s", rule.Change.Address, operation.Trust, rule.Change.Action, operation.Name, operation.Permission, operation.Certainty))
		}
	}
	return debug
}

// markRunContext marks coverage partial for an unresolved context, or for
// inspection checks that could not run in a resolved one.
func markRunContext(coverage *model.Coverage, run RunContext) {
	if !run.Resolved() {
		markContextUnresolved(coverage, run.Unresolved)
		return
	}
	if run.InspectionUnavailable != "" {
		markInspectionUnavailable(coverage, run.InspectionUnavailable)
	}
}

// PredictConflicts reports planned S3 buckets and IAM roles whose names AWS
// already has.
func PredictConflicts(ctx context.Context, config sdk.Config, rules []packs.ResolvedRule) ([]model.Finding, error) {
	buckets, err := conflicts.PredictBucketConflicts(ctx, config, rules)
	if err != nil {
		return nil, err
	}
	iamFindings, err := conflicts.PredictIAMNameConflicts(ctx, config, rules)
	if err != nil {
		return nil, err
	}
	return append(buckets, iamFindings...), nil
}

// defaultProviderOnly splits the changes, and their rules, into those on the
// default AWS provider and the AWS changes on any other configuration, aliased
// or unknown.
func defaultProviderOnly(changes []model.PlannedChange, rules []packs.ResolvedRule) ([]model.PlannedChange, []packs.ResolvedRule, []model.PlannedChange) {
	var inspected, aliased []model.PlannedChange
	others := map[string]bool{}
	for _, change := range changes {
		if model.NormalizeProvider(change.ProviderName) == model.ProviderAWS && !change.OnDefaultAWSProvider() {
			aliased = append(aliased, change)
			others[change.Address] = true
			continue
		}
		inspected = append(inspected, change)
	}
	var inspectedRules []packs.ResolvedRule
	for _, rule := range rules {
		if !others[rule.Change.Address] {
			inspectedRules = append(inspectedRules, rule)
		}
	}
	return inspected, inspectedRules, aliased
}

func containsAWSChanges(changes []model.PlannedChange) bool {
	for _, change := range changes {
		if model.NormalizeProvider(change.ProviderName) == model.ProviderAWS {
			return true
		}
	}
	return false
}

// permissionScope is where the apply creates resources: the run's partition and
// region, in the apply identity's account.
func (r RunContext) permissionScope() permissions.Scope {
	scope := permissions.Scope{Partition: r.Partition, Region: r.Region, Account: r.Account}
	if parsed, err := arn.Parse(r.Identity.ApplyIdentity); err == nil && parsed.AccountID != "" {
		scope.Account = parsed.AccountID
	}
	if scope.Partition == "" {
		scope.Partition = "aws"
	}
	return scope
}
