package aws

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/tfpreflight/tfpreflight/internal/checks/dependencies"
	"github.com/tfpreflight/tfpreflight/internal/plan"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// RunContext is the one AWS account and region a run inspects. Every check that
// calls AWS gets it, so no two checks answer about different places: a plan for
// eu-west-1 run from a shell set to us-east-1 would otherwise be half checked in
// each.
type RunContext struct {
	// Config is what every check builds its clients from. Its Region is Region.
	Config sdk.Config
	Region string
	// RegionSource is where Region came from: the provider block, var.<name>,
	// local.<name>, or the environment.
	RegionSource string
	Account      string
	Partition    string
	// Identity is the inspection identity and the apply identity whose
	// permissions are simulated. It is known even when the scope is not.
	Identity model.AWSContext
	// Unresolved says why the account or region is unknown. When it is set, no
	// check calls AWS and every AWS check is partial.
	Unresolved string
	// InspectionUnavailable says why conflicts, quotas and dependencies cannot
	// run although the account and region are known: the provider's role could
	// not be assumed. Permissions still run.
	InspectionUnavailable string
	// CredentialsError is the SDK's reason no credentials could be found, for
	// --debug.
	CredentialsError string
}

// Inspects reports whether the inspection checks may call AWS.
func (c RunContext) Inspects() bool { return c.Resolved() && c.InspectionUnavailable == "" }

// Resolved reports whether checks may call AWS.
func (c RunContext) Resolved() bool { return c.Unresolved == "" }

// contextSources is where the resolver reads the SDK configuration and the
// identities from, so tests can replace AWS.
type contextSources struct {
	LoadConfig func(context.Context) (sdk.Config, error)
	// Credentials says why config has no usable credentials, or nil. It may be
	// nil itself, and then the credentials are taken to work.
	Credentials    func(context.Context, sdk.Config) error
	CallerIdentity func(context.Context, sdk.Config) (string, error)
	Profile        func() string
	// RegionVariable reports whether the provider block's region is exactly
	// var.<name>; see plan.RegionVariable.
	RegionVariable func() (string, bool, error)
	// RegionLocal reports whether it is exactly local.<name>, a plain string;
	// see plan.RegionLocal.
	RegionLocal func() (name, value string, ok bool, err error)
	// AssumeRoleVariable does the same for assume_role.role_arn.
	AssumeRoleVariable func() (string, bool, error)
	RoleARN            func(context.Context, sdk.Config, string) (string, error)
	AssumeRole         func(ctx context.Context, config sdk.Config, role, externalID string) (sdk.Config, error)
}

func productionContextSources() contextSources {
	return contextSources{
		LoadConfig: func(ctx context.Context) (sdk.Config, error) { return awsconfig.LoadDefaultConfig(ctx) },
		Credentials: func(ctx context.Context, config sdk.Config) error {
			if config.Credentials == nil {
				return errors.New("no credential provider configured")
			}
			_, err := config.Credentials.Retrieve(ctx)
			return err
		},
		CallerIdentity: func(ctx context.Context, config sdk.Config) (string, error) {
			return callerIdentity(ctx, sts.NewFromConfig(config))
		},
		Profile: inspectionProfile,
		RegionVariable: func() (string, bool, error) {
			return plan.RegionVariable(".")
		},
		RegionLocal: func() (string, string, bool, error) {
			return plan.RegionLocal(".")
		},
		AssumeRoleVariable: func() (string, bool, error) {
			return plan.AssumeRoleVariable(".")
		},
		RoleARN:    roleARN,
		AssumeRole: assumeRole,
	}
}

// inspectionProfile is the shared-config profile the inspection credentials come
// from.
func inspectionProfile() string {
	profile := os.Getenv("AWS_PROFILE")
	if profile == "" {
		profile = os.Getenv("AWS_DEFAULT_PROFILE")
	}
	if profile == "" {
		profile = "default"
	}
	return profile
}

func resolveRunContext(ctx context.Context, sources contextSources, planJSON []byte, principal string) RunContext {
	config, err := sources.LoadConfig(ctx)
	if err != nil {
		run := RunContext{Identity: applyIdentity(ctx, sources, config, "", principal, dependencies.ProviderContext{}), Unresolved: "AWS configuration unavailable"}
		run.Identity.Unresolved = run.Unresolved
		return run
	}
	inspection, identityErr, credentialsErr := inspectionIdentity(ctx, sources, config)
	parsed, err := dependencies.ParsePlan(planJSON)
	if err != nil {
		run := RunContext{Identity: applyIdentity(ctx, sources, config, inspection, principal, dependencies.ProviderContext{})}
		run.Unresolved = "plan provider configuration unavailable"
		run.Identity.Unresolved = run.Unresolved
		return run
	}
	provider := parsed.DefaultContext
	run := RunContext{Identity: applyIdentity(ctx, sources, config, inspection, principal, provider)}
	// The account is the role's when the provider assumes one.
	accountIdentity := inspection
	role, _, roleReason := providerRole(provider, sources.AssumeRoleVariable)
	if role != "" {
		accountIdentity = role
	}
	scope := resolveScope(scopeInputs{
		Provider: provider, InspectionIdentity: accountIdentity, IdentityError: identityErr, NoCredentials: credentialsErr != nil, Profile: sources.Profile(),
		EnvironmentRegion: config.Region, RegionVariable: sources.RegionVariable, RegionLocal: sources.RegionLocal,
	})
	run.Region, run.RegionSource, run.Account, run.Partition, run.Unresolved = scope.Region, scope.RegionSource, scope.Account, scope.Partition, scope.Reason
	run.Identity.Region, run.Identity.RegionSource, run.Identity.Unresolved = scope.Region, scope.RegionSource, scope.Reason
	config.Region = run.Region
	run.Config = config
	// The inspection checks assume the provider's role, to look where it
	// applies. A role that cannot be named or assumed leaves them partial; it
	// never fails the run.
	switch {
	case provider.AssumeRole == nil || !run.Resolved():
	case role == "":
		run.InspectionUnavailable = "the provider assumes a role tfpreflight cannot name: " + roleReason
	case sources.AssumeRole == nil:
		run.InspectionUnavailable = "assuming the provider's role " + role + " is unavailable"
	default:
		assumed, err := sources.AssumeRole(ctx, config, role, provider.AssumeRole.ExternalID)
		if err != nil {
			run.InspectionUnavailable = "could not assume the provider's role " + role + ": " + err.Error()
		} else {
			run.Config = assumed
			run.Identity.AssumedRole = role
		}
	}
	run.Identity.InspectionUnavailable = run.InspectionUnavailable
	if credentialsErr != nil {
		run.noteMissingCredentials(credentialsErr)
	}
	return run
}

// inspectionIdentity asks STS who the inspection credentials are. The STS error
// is kept: an expired SSO token or a wrong profile is the usual reason the
// account is unknown, and the user needs to see it. With no credentials at
// all, STS is not asked, and credentialsErr says why.
func inspectionIdentity(ctx context.Context, sources contextSources, config sdk.Config) (identity string, identityErr, credentialsErr error) {
	if sources.Credentials != nil {
		if credentialsErr = sources.Credentials(ctx, config); credentialsErr != nil {
			return "", nil, credentialsErr
		}
	}
	identity, identityErr = sources.CallerIdentity(ctx, config)
	return identity, identityErr, nil
}

// noteMissingCredentials keeps the SDK's reason for --debug. Naming the apply
// role would not help: nothing can be checked without credentials.
func (c *RunContext) noteMissingCredentials(err error) {
	c.CredentialsError = err.Error()
	if !c.Identity.ApplyIdentityKnown {
		c.Identity.ApplyIdentityNote = "no AWS credentials were found, so permissions were not checked"
	}
}

type scope struct {
	Region, RegionSource, Account, Partition, Reason string
}

func (c RunContext) scope() scope {
	return scope{Region: c.Region, RegionSource: c.RegionSource, Account: c.Account, Partition: c.Partition, Reason: c.Unresolved}
}

type scopeInputs struct {
	Provider           dependencies.ProviderContext
	InspectionIdentity string
	// IdentityError is why STS could not name the inspection identity.
	IdentityError error
	// NoCredentials is set when there were no credentials to ask STS with.
	NoCredentials bool
	Profile       string
	// EnvironmentRegion is the region the SDK resolved from AWS_REGION,
	// AWS_DEFAULT_REGION or the profile: where the provider looks too.
	EnvironmentRegion string
	// RegionVariable and RegionLocal may be nil, and then a variable or local
	// region is unproven.
	RegionVariable func() (string, bool, error)
	RegionLocal    func() (name, value string, ok bool, err error)
}

// Region sources, as reported.
const (
	RegionFromProvider    = "provider block"
	RegionFromEnvironment = "environment"
)

// resolveScope decides whether the inspection credentials answer for the account
// and region Terraform applies to.
//
// The region is resolved as Terraform resolves the provider's: a literal in the
// provider block; region = var.<name>, from the value the plan recorded;
// region = local.<name>, when that local is a plain string; with no region in
// the block, the environment. Anything else, such as functions, a computed local
// or a variable without a value, is unresolved: a guess would send lookups to a
// region the apply never touches, where "not found" means nothing.
func resolveScope(in scopeInputs) scope {
	var resolved scope
	var regionReason string
	resolved.Region, resolved.RegionSource, regionReason = resolveRegion(in)
	if identity, err := arn.Parse(in.InspectionIdentity); err == nil {
		resolved.Account = identity.AccountID
		resolved.Partition = identity.Partition
	}
	resolved.Reason = scopeReason(in, resolved.Account, regionReason)
	return resolved
}

// scopeReason is why the inspection credentials may not answer for the apply, or
// "". Missing credentials come first; then the account: an account the provider
// refuses, then a different profile, then no account; then the provider
// context, then the region.
func scopeReason(in scopeInputs, account, regionReason string) string {
	provider := in.Provider
	switch {
	case in.NoCredentials:
		return "no AWS credentials found"
	case len(provider.AllowedAccounts) > 0 && !slices.Contains(provider.AllowedAccounts, account):
		return "inspection account does not satisfy provider allowed_account_ids"
	case provider.Profile != "" && provider.Profile != in.Profile:
		return "Terraform provider profile differs from inspection profile; account equivalence unproven"
	case account == "" && in.IdentityError != nil:
		return "inspection account identity unavailable: " + in.IdentityError.Error()
	case account == "":
		return "inspection account identity unavailable"
	case provider.Reason != "":
		return provider.Reason
	default:
		return regionReason
	}
}

func resolveRegion(in scopeInputs) (region, source, reason string) {
	provider := in.Provider
	switch provider.RegionKind {
	case dependencies.RegionLiteral:
		return provider.Region, RegionFromProvider, ""
	case dependencies.RegionAbsent:
		if in.EnvironmentRegion == "" {
			return "", "", "the provider block sets no region and none is set in the environment (AWS_REGION, AWS_DEFAULT_REGION or the profile)"
		}
		return in.EnvironmentRegion, RegionFromEnvironment, ""
	case dependencies.RegionReferences:
		if name, single := singleLocal(provider.RegionReferences); single {
			return regionFromLocal(name, in.RegionLocal)
		}
		return regionFromVariable(provider, in.RegionVariable)
	case dependencies.RegionOther:
		return "", "", "provider region is an expression tfpreflight cannot evaluate" + onlyPlainRegions
	default:
		return "", "", ""
	}
}

// onlyPlainRegions ends every reason a provider region could not be resolved.
const onlyPlainRegions = "; only a literal, a bare variable, or a local set to a plain string can be resolved"

// regionFromLocal resolves region = local.<name> when that local is a plain
// string in the root module.
func regionFromLocal(name string, readSource func() (string, string, bool, error)) (region, source, reason string) {
	computed := "provider region is computed from local." + name + onlyPlainRegions
	if readSource == nil {
		return "", "", computed
	}
	direct, value, ok, err := readSource()
	switch {
	case err != nil:
		return "", "", "provider region references local." + name + " but the configuration could not be read: " + err.Error()
	case !ok || direct != name:
		return "", "", computed
	}
	return value, "local." + name, ""
}

// singleLocal is the local an expression references, when it references
// exactly one thing and that is a local value.
func singleLocal(references []string) (string, bool) {
	if len(references) != 1 {
		return "", false
	}
	name, isLocal := strings.CutPrefix(references[0], "local.")
	if !isLocal || strings.ContainsAny(name, ".[") {
		return "", false
	}
	return name, true
}

// regionFromVariable resolves a provider region that references variables,
// worded like every other region reason.
func regionFromVariable(provider dependencies.ProviderContext, readSource func() (string, bool, error)) (region, source, reason string) {
	const subject = "provider region"
	const onlyDirect = onlyPlainRegions
	name, value, problem, err := directVariable(provider.RegionReferences, readSource, provider.Variables)
	switch problem {
	case variableComputed:
		return "", "", subject + " is computed from " + strings.Join(provider.RegionReferences, ", ") + onlyDirect
	case variableSourceUnavailable:
		return "", "", subject + " references var." + name + " but the provider block source is unavailable to confirm it is used as-is"
	case variableSourceUnreadable:
		return "", "", subject + " references var." + name + " but the provider block could not be read: " + err.Error()
	case variableNotDirect:
		return "", "", subject + " is an expression of var." + name + ", not the variable itself" + onlyDirect
	case variableUnrecorded:
		return "", "", subject + " is var." + name + " but the plan records no value for it"
	case variableNotText:
		return "", "", subject + " is var." + name + " but its value in the plan is not a non-empty string"
	}
	return value, "var." + name, ""
}

// variableProblem is why a provider argument could not be read as exactly one
// root variable.
type variableProblem int

const (
	variableFound variableProblem = iota
	variableComputed
	variableSourceUnavailable
	variableSourceUnreadable
	variableNotDirect
	variableUnrecorded
	variableNotText
)

// directVariable reads a provider argument as exactly var.<name>, with the value
// the plan recorded. The plan JSON records region = var.region and region =
// format("%s", var.region) alike, so readSource reads the provider block itself
// to confirm the variable is used as is. err is set only with
// variableSourceUnreadable.
func directVariable(references []string, readSource func() (string, bool, error), variables map[string]any) (name, value string, problem variableProblem, err error) {
	name, single := singleVariable(references)
	if !single {
		return name, "", variableComputed, nil
	}
	if readSource == nil {
		return name, "", variableSourceUnavailable, nil
	}
	direct, ok, err := readSource()
	if err != nil {
		return name, "", variableSourceUnreadable, err
	}
	if !ok || direct != name {
		return name, "", variableNotDirect, nil
	}
	recorded, present := variables[name]
	if !present {
		return name, "", variableUnrecorded, nil
	}
	text, isText := recorded.(string)
	if !isText || text == "" {
		return name, "", variableNotText, nil
	}
	return name, text, variableFound, nil
}

// singleVariable is the root variable an expression references, when it
// references exactly one thing and that is a variable.
func singleVariable(references []string) (string, bool) {
	name := ""
	for _, reference := range references {
		variable, isVariable := strings.CutPrefix(reference, "var.")
		if !isVariable || strings.ContainsAny(variable, ".[") || (name != "" && variable != name) {
			return "", false
		}
		name = variable
	}
	return name, name != ""
}

// markContextUnresolved makes every AWS check that applies to a resource
// partial, with the reason. A check that does not apply, or has no knowledge, is
// left alone: the missing context is not why it has no answer.
func markContextUnresolved(coverage *model.Coverage, reason string) {
	for index := range coverage.Resources {
		resource := &coverage.Resources[index]
		for _, status := range []*model.CheckStatus{&resource.Permissions, &resource.Conflicts, &resource.Quota} {
			switch *status {
			case model.CheckNotApplicable, model.CheckUnsupported, model.CheckUnverifiable, model.CheckNoQuotaRule, "":
			default:
				*status = model.CheckPartialAWSContext
			}
		}
		resource.UnresolvedAWSContext = reason
	}
}

// markAliased makes every AWS check partial for a resource on a provider
// configuration other than the default, whose account and region the run does
// not reconstruct.
func markAliased(coverage *model.Coverage, aliased []model.PlannedChange) {
	addresses := map[string]bool{}
	for _, change := range aliased {
		addresses[change.Address] = true
	}
	for index := range coverage.Resources {
		resource := &coverage.Resources[index]
		if !addresses[resource.Resource] {
			continue
		}
		for _, status := range []*model.CheckStatus{&resource.Permissions, &resource.Conflicts, &resource.Quota} {
			switch *status {
			case model.CheckNotApplicable, model.CheckUnsupported, model.CheckNoQuotaRule, "":
			default:
				*status = model.CheckPartialAWSContext
			}
		}
		resource.UnresolvedAWSContext = model.AliasedProviderReason
	}
}

// markInspectionUnavailable makes conflicts and quotas partial, with the reason.
// Permissions are simulated either way.
func markInspectionUnavailable(coverage *model.Coverage, reason string) {
	for index := range coverage.Resources {
		resource := &coverage.Resources[index]
		for _, status := range []*model.CheckStatus{&resource.Conflicts, &resource.Quota} {
			switch *status {
			case model.CheckNotApplicable, model.CheckUnsupported, model.CheckUnverifiable, model.CheckNoQuotaRule, "":
			default:
				*status = model.CheckPartialAWSContext
			}
		}
		resource.UnresolvedAWSContext = reason
	}
}
