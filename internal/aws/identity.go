package aws

import (
	"context"
	"strings"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/tfpreflight/tfpreflight/internal/checks/dependencies"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

type stsIdentityAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// callerIdentity is the ARN of the credentials inspecting AWS.
func callerIdentity(ctx context.Context, client stsIdentityAPI) (string, error) {
	caller, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || caller.Arn == nil {
		return "", err
	}
	return *caller.Arn, nil
}

// Where the apply identity came from.
const (
	IdentityFromFlag       = "--principal"
	IdentityFromAssumeRole = "provider assume_role"
	IdentityFromInspection = "inspection identity"
	IdentityFromSession    = "inspection identity's role session"
)

// howToPassPrincipal ends every note about an unknown apply identity.
const howToPassPrincipal = "permissions were not checked; pass --principal <ARN of the IAM role or user terraform applies with>"

// providerRole is the role the provider assumes, resolved like the region: a
// literal, or exactly var.<name> with the value the plan recorded. When it
// cannot be named, role is empty and reason says why.
func providerRole(provider dependencies.ProviderContext, variable func() (string, bool, error), local func() (string, string, bool, error)) (role, source, reason string) {
	assume := provider.AssumeRole
	if assume == nil {
		return "", "", ""
	}
	if assume.Unresolved != "" {
		return "", "", assume.Unresolved
	}
	if assume.RoleARN != "" {
		return assume.RoleARN, IdentityFromAssumeRole, ""
	}
	const subject = "the provider's assume_role.role_arn"
	if name, single := singleLocal(assume.RoleARNReferences); single {
		value, source, reason := valueFromLocal(subject, name, local)
		if reason != "" {
			return "", "", reason
		}
		return value, IdentityFromAssumeRole + " (" + source + ")", ""
	}
	name, value, problem, _ := directVariable(assume.RoleARNReferences, variable, provider.Variables)
	switch problem {
	case variableComputed:
		return "", "", subject + " is computed from " + strings.Join(assume.RoleARNReferences, ", ")
	case variableSourceUnavailable:
		return "", "", subject + " references var." + name + " but the provider block source is unavailable"
	case variableSourceUnreadable, variableNotDirect:
		return "", "", subject + " is an expression of var." + name + ", not the variable itself"
	case variableUnrecorded, variableNotText:
		return "", "", subject + " is var." + name + " but the plan records no value for it"
	}
	return value, IdentityFromAssumeRole + " (var." + name + ")", ""
}

// applyIdentity decides who applies: --principal, else the provider's role, else
// the inspection identity (an assumed-role session, SSO included, standing for
// its role), else nobody, with how to say.
func applyIdentity(ctx context.Context, sources contextSources, config sdk.Config, inspection, principal string, provider dependencies.ProviderContext) model.AWSContext {
	identity := model.AWSContext{InspectionIdentity: inspection}
	if principal != "" {
		return withApplyIdentity(identity, principal, IdentityFromFlag, "")
	}
	if provider.AssumeRole != nil {
		role, source, reason := providerRole(provider, sources.AssumeRoleVariable, sources.AssumeRoleLocal)
		if role == "" {
			identity.ApplyIdentityNote = "the provider assumes a role tfpreflight cannot name: " + reason + "; " + howToPassPrincipal
			return identity
		}
		note := ""
		if provider.AssumeRole.SessionPolicy {
			note = "the provider narrows this role with a session policy, which the simulation does not include"
		}
		return withApplyIdentity(identity, role, source, note)
	}
	return inspectionApplyIdentity(ctx, sources, config, identity)
}

func withApplyIdentity(identity model.AWSContext, arn, source, note string) model.AWSContext {
	identity.ApplyIdentity, identity.ApplyIdentityKnown, identity.ApplyIdentitySource, identity.ApplyIdentityNote = arn, true, source, note
	return identity
}

// inspectionApplyIdentity uses the inspection identity when it is an IAM role or
// user, or a role session.
func inspectionApplyIdentity(ctx context.Context, sources contextSources, config sdk.Config, identity model.AWSContext) model.AWSContext {
	inspection := identity.InspectionIdentity
	parsed, err := arn.Parse(inspection)
	switch {
	case err != nil:
		// Without an inspection identity no check runs, so naming the apply
		// identity would not help.
		identity.ApplyIdentityNote = "the inspection identity is unavailable, so permissions were not checked"
	case parsed.Service == "iam" && (strings.HasPrefix(parsed.Resource, "role/") || strings.HasPrefix(parsed.Resource, "user/")):
		return withApplyIdentity(identity, inspection, IdentityFromInspection, "")
	case parsed.Service == "sts" && strings.HasPrefix(parsed.Resource, "assumed-role/"):
		role, note := sessionRole(ctx, sources, config, parsed)
		return withApplyIdentity(identity, role, IdentityFromSession, note)
	default:
		identity.ApplyIdentityNote = "the inspection identity (" + inspection + ") is not an IAM role or user; " + howToPassPrincipal
	}
	return identity
}

// sessionRole is the role behind an assumed-role session ARN. Without IAM's
// answer for the role's path, the path is assumed, with a note.
func sessionRole(ctx context.Context, sources contextSources, config sdk.Config, session arn.ARN) (role, note string) {
	roleName := strings.SplitN(strings.TrimPrefix(session.Resource, "assumed-role/"), "/", 2)[0]
	if sources.RoleARN != nil {
		if role, err := sources.RoleARN(ctx, config, roleName); err == nil && role != "" {
			return role, ""
		}
	}
	// IAM did not say the role's path. SSO roles live under a fixed one.
	path := ""
	note = "the role's path could not be read (iam:GetRole), so it is assumed to have none"
	if strings.HasPrefix(roleName, "AWSReservedSSO_") {
		path, note = "aws-reserved/sso.amazonaws.com/", "the role's path could not be read (iam:GetRole); SSO roles are under aws-reserved/sso.amazonaws.com/"
	}
	return arn.ARN{Partition: session.Partition, Service: "iam", AccountID: session.AccountID, Resource: "role/" + path + roleName}.String(), note
}

func roleARN(ctx context.Context, config sdk.Config, name string) (string, error) {
	output, err := iam.NewFromConfig(config).GetRole(ctx, &iam.GetRoleInput{RoleName: &name})
	if err != nil || output.Role == nil || output.Role.Arn == nil {
		return "", err
	}
	return *output.Role.Arn, nil
}

// assumeRole returns configuration with the role's credentials, checked with one
// call so a failure shows now rather than in every check.
func assumeRole(ctx context.Context, config sdk.Config, role, externalID string) (sdk.Config, error) {
	assumed := config.Copy()
	provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(config), role, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = "tfpreflight"
		if externalID != "" {
			o.ExternalID = sdk.String(externalID)
		}
	})
	assumed.Credentials = sdk.NewCredentialsCache(provider)
	if _, err := assumed.Credentials.Retrieve(ctx); err != nil {
		return config, err
	}
	return assumed, nil
}
