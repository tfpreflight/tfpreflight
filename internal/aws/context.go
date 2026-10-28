package aws

import (
	"context"
	"errors"
	"os"
	"slices"
	"strconv"
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
	// Profile is the shared-config profile the provider block names, which the
	// inspection credentials are read from, and ProfileSource where it came
	// from: the provider block, var.<name> or local.<name>. Both are empty when
	// the provider names none and the environment's credentials are used.
	Profile       string
	ProfileSource string
	Account       string
	Partition     string
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
	// LoadConfig loads the SDK configuration, from the shared-config profile
	// when profile is set and from the environment's otherwise.
	LoadConfig func(ctx context.Context, profile string) (sdk.Config, error)
	// Credentials says why config has no usable credentials, or nil. It may be
	// nil itself, and then the credentials are taken to work.
	Credentials    func(context.Context, sdk.Config) error
	CallerIdentity func(context.Context, sdk.Config) (string, error)
	Profile        func() string
	// EnvProfile is the profile AWS_PROFILE or AWS_DEFAULT_PROFILE selects, with
	// the variable's name, or "" when neither is set. It may be nil.
	EnvProfile func() (name, variable string)
	// RegionVariable reports whether the provider block's region is exactly
	// var.<name>; see plan.RegionVariable.
	RegionVariable func() (string, bool, error)
	// RegionLocal reports whether it is exactly local.<name>, a plain string;
	// see plan.RegionLocal.
	RegionLocal func() (name, value string, ok bool, err error)
	// ProfileVariable and ProfileLocal do the same for the provider's profile.
	ProfileVariable func() (string, bool, error)
	ProfileLocal    func() (name, value string, ok bool, err error)
	// AssumeRoleVariable and AssumeRoleLocal do the same for
	// assume_role.role_arn, and ExternalIDVariable and ExternalIDLocal for
	// assume_role.external_id.
	AssumeRoleVariable func() (string, bool, error)
	AssumeRoleLocal    func() (name, value string, ok bool, err error)
	ExternalIDVariable func() (string, bool, error)
	ExternalIDLocal    func() (name, value string, ok bool, err error)
	// AllowedAccountsList reads how the provider block writes
	// allowed_account_ids; see plan.ProviderStringList.
	AllowedAccountsList func() (items []plan.StringListItem, wholeVar string, ok bool, err error)
	RoleARN             func(context.Context, sdk.Config, string) (string, error)
	AssumeRole          func(ctx context.Context, config sdk.Config, role, externalID string) (sdk.Config, error)
}

func productionContextSources() contextSources {
	return contextSources{
		LoadConfig: func(ctx context.Context, profile string) (sdk.Config, error) {
			if profile == "" {
				return awsconfig.LoadDefaultConfig(ctx)
			}
			return awsconfig.LoadDefaultConfig(ctx, awsconfig.WithSharedConfigProfile(profile))
		},
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
		Profile:    inspectionProfile,
		EnvProfile: envProfile,
		RegionVariable: func() (string, bool, error) {
			return plan.RegionVariable(".")
		},
		RegionLocal: func() (string, string, bool, error) {
			return plan.RegionLocal(".")
		},
		ProfileVariable: func() (string, bool, error) {
			return plan.ProviderVariable(".", "", "profile")
		},
		ProfileLocal: func() (string, string, bool, error) {
			return plan.ProviderLocal(".", "", "profile")
		},
		AssumeRoleVariable: func() (string, bool, error) {
			return plan.AssumeRoleVariable(".")
		},
		AssumeRoleLocal: func() (string, string, bool, error) {
			return plan.ProviderLocal(".", "assume_role", "role_arn")
		},
		ExternalIDVariable: func() (string, bool, error) {
			return plan.ProviderVariable(".", "assume_role", "external_id")
		},
		ExternalIDLocal: func() (string, string, bool, error) {
			return plan.ProviderLocal(".", "assume_role", "external_id")
		},
		AllowedAccountsList: func() ([]plan.StringListItem, string, bool, error) {
			return plan.ProviderStringList(".", "", "allowed_account_ids")
		},
		RoleARN:    roleARN,
		AssumeRole: assumeRole,
	}
}

// inspectionProfile is the shared-config profile the inspection credentials come
// from.
func inspectionProfile() string {
	if profile, _ := envProfile(); profile != "" {
		return profile
	}
	return "default"
}

// envProfile is the profile the environment selects, and the variable that
// does, or "" when it selects none.
func envProfile() (name, variable string) {
	for _, variable := range []string{"AWS_PROFILE", "AWS_DEFAULT_PROFILE"} {
		if name := os.Getenv(variable); name != "" {
			return name, variable
		}
	}
	return "", ""
}

func resolveRunContext(ctx context.Context, sources contextSources, planJSON []byte, principal string) RunContext {
	parsed, parseErr := dependencies.ParsePlan(planJSON)
	provider := parsed.DefaultContext
	// The inspection credentials come from the profile the provider block
	// names, as Terraform's do: no other profile can be shown to be the same
	// account. Without one, they come from the environment.
	inputs := scopeInputs{Provider: provider, ProfileVariable: sources.ProfileVariable, ProfileLocal: sources.ProfileLocal, AllowedAccountsList: sources.AllowedAccountsList}
	profile, profileSource, _ := resolveProfile(inputs)
	selected, selectedFrom := selectedProfile(sources, profile, profileSource)
	config, err := sources.LoadConfig(ctx, profile)
	if err != nil {
		return unresolvedRunContext(applyIdentity(ctx, sources, config, "", principal, dependencies.ProviderContext{}), configFailure(selected, selectedFrom, err))
	}
	inspection, identityErr, credentialsErr := inspectionIdentity(ctx, sources, config)
	if parseErr != nil {
		return unresolvedRunContext(applyIdentity(ctx, sources, config, inspection, principal, dependencies.ProviderContext{}), "plan provider configuration unavailable")
	}
	run := RunContext{Identity: applyIdentity(ctx, sources, config, inspection, principal, provider), Profile: profile, ProfileSource: profileSource}
	// The account is the role's when the provider assumes one.
	accountIdentity := inspection
	role, _, roleReason := providerRole(provider, sources.AssumeRoleVariable, sources.AssumeRoleLocal)
	if role != "" {
		accountIdentity = role
	}
	inputs.InspectionIdentity, inputs.IdentityError, inputs.NoCredentials = accountIdentity, identityErr, credentialsErr != nil
	inputs.Profile = profile
	if profile == "" {
		inputs.Profile = sources.Profile()
	}
	if credentialsErr != nil {
		inputs.CredentialsProblem = credentialsProblem(selected, selectedFrom, credentialsErr)
	}
	inputs.EnvironmentRegion, inputs.RegionVariable, inputs.RegionLocal = config.Region, sources.RegionVariable, sources.RegionLocal
	scope := resolveScope(inputs)
	run.Region, run.RegionSource, run.Account, run.Partition, run.Unresolved = scope.Region, scope.RegionSource, scope.Account, scope.Partition, scope.Reason
	run.Identity.Region, run.Identity.RegionSource, run.Identity.Unresolved = scope.Region, scope.RegionSource, scope.Reason
	config.Region = run.Region
	run.Config = config
	run.assumeProviderRole(ctx, sources, provider, role, roleReason)
	run.Identity.InspectionUnavailable = run.InspectionUnavailable
	if credentialsErr != nil {
		run.noteMissingCredentials(credentialsErr)
	}
	return run
}

// unresolvedRunContext is a run that cannot name where it inspects.
func unresolvedRunContext(identity model.AWSContext, reason string) RunContext {
	run := RunContext{Identity: identity, Unresolved: reason}
	run.Identity.Unresolved = reason
	return run
}

// selectedProfile is the profile the user chose on purpose, and where: the one
// the provider block names, else the one AWS_PROFILE selects. It is empty when
// the credentials come from the SDK's default chain with nothing chosen.
func selectedProfile(sources contextSources, profile, profileSource string) (name, from string) {
	if profile != "" {
		return profile, profileSource
	}
	if sources.EnvProfile != nil {
		return sources.EnvProfile()
	}
	return "", ""
}

// configFailure is why the SDK configuration could not be loaded, naming the
// profile that was chosen when there is one. The SDK's own words are kept: they
// say what is wrong with the AWS config.
func configFailure(selected, selectedFrom string, err error) string {
	if selected == "" {
		return "AWS configuration unavailable: " + err.Error()
	}
	return "AWS profile " + strconv.Quote(selected) + " (from " + selectedFrom + ") could not be loaded: " + err.Error()
}

// ssoLoginNeeded are the SDK's words for an SSO login that is missing, expired
// or unreadable, as opposed to one that failed for another reason, such as the
// portal being unreachable.
var ssoLoginNeeded = []string{
	"the SSO session has expired or is invalid",
	"cached SSO token is expired, or not present",
	"failed to read cached SSO token file",
	"failed to parse cached SSO token file",
}

// credentialsProblem is why a profile that was chosen on purpose gave no
// credentials, in the SDK's words, with the command that fixes an SSO login.
// It is empty when no profile was chosen: then nothing was configured, and "no
// AWS credentials found" is the whole story.
func credentialsProblem(selected, selectedFrom string, err error) string {
	if selected == "" {
		return ""
	}
	subject := "AWS profile " + strconv.Quote(selected) + " (from " + selectedFrom + ") has no usable credentials: "
	reason := strings.TrimPrefix(err.Error(), "failed to refresh cached credentials, ")
	for _, phrase := range ssoLoginNeeded {
		if strings.Contains(reason, phrase) {
			return subject + "the SSO login has expired or was never done; run: aws sso login --profile " + selected
		}
	}
	if runes := []rune(reason); len(runes) > maxCredentialsReason {
		reason = string(runes[:maxCredentialsReason]) + "…"
	}
	return subject + reason
}

// maxCredentialsReason keeps the SDK's wording from burying the result line;
// --debug has all of it.
const maxCredentialsReason = 240

// assumeProviderRole makes the inspection checks look as the role the provider
// assumes, to look where it applies. A role that cannot be named or assumed
// leaves them partial; it never fails the run.
func (c *RunContext) assumeProviderRole(ctx context.Context, sources contextSources, provider dependencies.ProviderContext, role, roleReason string) {
	switch {
	case provider.AssumeRole == nil || !c.Resolved():
	case role == "":
		c.InspectionUnavailable = "the provider assumes a role tfpreflight cannot name: " + roleReason
	case sources.AssumeRole == nil:
		c.InspectionUnavailable = "assuming the provider's role " + role + " is unavailable"
	default:
		externalID, reason := providerExternalID(provider, sources.ExternalIDVariable, sources.ExternalIDLocal)
		if reason != "" {
			c.InspectionUnavailable = "the provider assumes a role tfpreflight cannot assume: " + reason
			return
		}
		assumed, err := sources.AssumeRole(ctx, c.Config, role, externalID)
		if err != nil {
			c.InspectionUnavailable = "could not assume the provider's role " + role + ": " + err.Error()
			return
		}
		c.Config = assumed
		c.Identity.AssumedRole = role
	}
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
	// Profile is the shared-config profile the inspection credentials come
	// from.
	Profile string
	// CredentialsProblem is why NoCredentials, worded for a profile that was
	// selected on purpose; it is empty when none was, and then the reason is the
	// plain "no AWS credentials found".
	CredentialsProblem string
	// ProfileVariable and ProfileLocal may be nil, and then a variable or local
	// profile is unproven.
	ProfileVariable func() (string, bool, error)
	ProfileLocal    func() (name, value string, ok bool, err error)
	// AllowedAccountsList may be nil, and then an allowed_account_ids that
	// references a variable or a local is unproven.
	AllowedAccountsList func() (items []plan.StringListItem, wholeVar string, ok bool, err error)
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
	profile, _, profileReason := resolveProfile(in)
	// The accounts the provider allows are decided here too. One that cannot be
	// resolved is the provider context's own reason, which comes after the
	// account checks.
	accounts, accountsReason := resolveAllowedAccounts(in)
	in.Provider.AllowedAccounts = accounts
	if in.Provider.Reason == "" {
		in.Provider.Reason = accountsReason
	}
	if identity, err := arn.Parse(in.InspectionIdentity); err == nil {
		resolved.Account = identity.AccountID
		resolved.Partition = identity.Partition
	}
	resolved.Reason = scopeReason(in, resolved.Account, regionReason, profile, profileReason)
	return resolved
}

// scopeReason is why the inspection credentials may not answer for the apply, or
// "". A provider profile that cannot be resolved comes first, since the
// credentials may not be the provider's; then missing credentials; then the
// account: an account the provider refuses, then a different profile, then no
// account; then the provider context, then the region.
func scopeReason(in scopeInputs, account, regionReason, profile, profileReason string) string {
	provider := in.Provider
	switch {
	case profileReason != "":
		return profileReason
	case in.NoCredentials && in.CredentialsProblem != "":
		return in.CredentialsProblem
	case in.NoCredentials:
		return "no AWS credentials found"
	case len(provider.AllowedAccounts) > 0 && !slices.Contains(provider.AllowedAccounts, account):
		return "inspection account does not satisfy provider allowed_account_ids"
	case profile != "" && profile != in.Profile:
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
			return valueFromLocal(regionSubject, name, in.RegionLocal)
		}
		return valueFromVariable(regionSubject, provider.RegionReferences, in.RegionVariable, provider.Variables)
	case dependencies.RegionOther:
		return "", "", regionSubject + " is an expression tfpreflight cannot evaluate" + onlyPlainValues
	default:
		return "", "", ""
	}
}

// Profile sources, as reported.
const profileFromProvider = "provider block"

// resolveProfile decides which shared-config profile the provider uses, the way
// resolveRegion decides the region: a literal in the provider block;
// profile = var.<name>, from the value the plan recorded; profile =
// local.<name>, when that local is a plain string. No profile, or a variable
// the plan records as null or empty, means the provider takes the environment's
// credentials, as Terraform does. Anything else is unresolved: the credentials
// may then belong to another account than the apply's.
func resolveProfile(in scopeInputs) (profile, source, reason string) {
	provider := in.Provider
	switch {
	case provider.Profile != "":
		return provider.Profile, profileFromProvider, ""
	case provider.ProfileKind == dependencies.ArgumentReferences:
		if name, single := singleLocal(provider.ProfileReferences); single {
			return valueFromLocal(profileSubject, name, in.ProfileLocal)
		}
		return profileFromVariable(provider, in.ProfileVariable)
	case provider.ProfileKind == dependencies.ArgumentOther:
		return "", "", profileSubject + " is an expression tfpreflight cannot evaluate" + onlyPlainValues
	default:
		return "", "", ""
	}
}

// profileFromVariable is valueFromVariable for the profile, where a variable
// the plan records as null or empty is no profile at all: Terraform then sets
// none, and the provider takes the environment's credentials.
func profileFromVariable(provider dependencies.ProviderContext, readSource func() (string, bool, error)) (profile, source, reason string) {
	name, text, problem, err := directVariable(provider.ProfileReferences, readSource, provider.Variables)
	switch recorded := provider.Variables[name]; {
	case problem == variableFound:
		return text, "var." + name, ""
	case problem == variableNotText && (recorded == nil || recorded == ""):
		return "", "", ""
	default:
		return "", "", variableReason(profileSubject, provider.ProfileReferences, name, problem, err)
	}
}

// The arguments the resolver names in its reasons.
const (
	regionSubject  = "provider region"
	profileSubject = "provider profile"
)

// onlyPlainValues ends every reason a provider argument could not be resolved.
const onlyPlainValues = "; only a literal, a bare variable, or a local set to a plain string can be resolved"

// valueFromLocal resolves an argument that is local.<name> when that local is a
// plain string in the root module.
func valueFromLocal(subject, name string, readSource func() (string, string, bool, error)) (value, source, reason string) {
	computed := subject + " is computed from local." + name + onlyPlainValues
	if readSource == nil {
		return "", "", computed
	}
	direct, text, ok, err := readSource()
	switch {
	case err != nil:
		return "", "", subject + " references local." + name + " but the configuration could not be read: " + err.Error()
	case !ok || direct != name:
		return "", "", computed
	}
	return text, "local." + name, ""
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

// valueFromVariable resolves an argument that references variables, worded like
// every other reason.
func valueFromVariable(subject string, references []string, readSource func() (string, bool, error), variables map[string]any) (value, source, reason string) {
	name, text, problem, err := directVariable(references, readSource, variables)
	if problem != variableFound {
		return "", "", variableReason(subject, references, name, problem, err)
	}
	return text, "var." + name, ""
}

// variableReason is why an argument could not be read as exactly one root
// variable with a value.
func variableReason(subject string, references []string, name string, problem variableProblem, err error) string {
	switch problem {
	case variableComputed:
		return subject + " is computed from " + strings.Join(references, ", ") + onlyPlainValues
	case variableSourceUnavailable:
		return subject + " references var." + name + " but the provider block source is unavailable to confirm it is used as-is"
	case variableSourceUnreadable:
		return subject + " references var." + name + " but the provider block could not be read: " + err.Error()
	case variableNotDirect:
		return subject + " is an expression of var." + name + ", not the variable itself" + onlyPlainValues
	case variableUnrecorded:
		return subject + " is var." + name + " but the plan records no value for it"
	case variableNotText:
		return subject + " is var." + name + " but its value in the plan is not a non-empty string"
	}
	return ""
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
