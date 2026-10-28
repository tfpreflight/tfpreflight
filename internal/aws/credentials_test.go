package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
)

// The reason a chosen profile gave no credentials is the SDK's, with the command
// that fixes an SSO login, and only when the SDK says the login is the problem.
func TestCredentialsProblemSaysWhatTheSDKSaid(t *testing.T) {
	const subject = `AWS profile "dev" (from AWS_PROFILE) has no usable credentials: `
	const login = "the SSO login has expired or was never done; run: aws sso login --profile dev"
	for name, tc := range map[string]struct {
		err  string
		want string
	}{
		"session expired":     {"failed to refresh cached credentials, the SSO session has expired or is invalid: token expired", subject + login},
		"token expired":       {"failed to refresh cached credentials, cached SSO token is expired, or not present, and cannot be refreshed", subject + login},
		"never logged in":     {"failed to refresh cached credentials, failed to read cached SSO token file, open /home/x/.aws/sso/cache/a.json: no such file or directory", subject + login},
		"unreadable token":    {"failed to refresh cached credentials, failed to parse cached SSO token file, invalid character", subject + login},
		"portal unreachable":  {"failed to refresh cached credentials, operation error SSO: GetRoleCredentials, dial tcp: lookup portal.sso.eu-west-1.amazonaws.com: no such host", subject + "operation error SSO: GetRoleCredentials, dial tcp: lookup portal.sso.eu-west-1.amazonaws.com: no such host"},
		"refresh unreachable": {"failed to refresh cached credentials, refresh cached SSO token failed, operation error SSO OIDC: CreateToken, dial tcp: i/o timeout", subject + "refresh cached SSO token failed, operation error SSO OIDC: CreateToken, dial tcp: i/o timeout"},
		"credential process":  {"failed to refresh cached credentials, credential process exited with status 1", subject + "credential process exited with status 1"},
		"no prefix to remove": {"no credential provider configured", subject + "no credential provider configured"},
		"long reason is cut":  {strings.Repeat("é", maxCredentialsReason+50), subject + strings.Repeat("é", maxCredentialsReason) + "…"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := credentialsProblem("dev", "AWS_PROFILE", errors.New(tc.err)); got != tc.want {
				t.Errorf("credentialsProblem = %q\nwant %q", got, tc.want)
			}
		})
	}
}

// With no profile chosen, nothing was configured and the plain reason stands.
func TestCredentialsProblemIsEmptyWhenNothingWasChosen(t *testing.T) {
	if got := credentialsProblem("", "", errors.New("failed to refresh cached credentials, no EC2 IMDS role found")); got != "" {
		t.Fatalf("credentialsProblem = %q, want none", got)
	}
}

// A configuration that cannot be loaded keeps the SDK's reason, and names the
// profile when one was chosen.
func TestConfigFailureKeepsTheSDKsReason(t *testing.T) {
	err := errors.New("failed to get shared config profile, dev")
	if got, want := configFailure("dev", "AWS_PROFILE", err), `AWS profile "dev" (from AWS_PROFILE) could not be loaded: failed to get shared config profile, dev`; got != want {
		t.Errorf("configFailure = %q, want %q", got, want)
	}
	if got, want := configFailure("", "", err), "AWS configuration unavailable: failed to get shared config profile, dev"; got != want {
		t.Errorf("configFailure = %q, want %q", got, want)
	}
}

// A run whose AWS_PROFILE gave no credentials says why; one with nothing chosen
// keeps the plain reason; and the provider's profile wins over AWS_PROFILE.
func TestRunNamesTheProfileThatGaveNoCredentials(t *testing.T) {
	failing := func(sources contextSources) contextSources {
		sources.Credentials = func(context.Context, sdk.Config) error {
			return errors.New("failed to refresh cached credentials, the SSO session has expired or is invalid")
		}
		return sources
	}
	plan := profilePlan("", `"region":{"value":"eu-west-1"}`)
	t.Run("AWS_PROFILE", func(t *testing.T) {
		sources := failing(contextSourcesFor(""))
		sources.EnvProfile = func() (string, string) { return "dev", "AWS_PROFILE" }
		run := resolveRunContext(context.Background(), sources, plan, "")
		const want = `AWS profile "dev" (from AWS_PROFILE) has no usable credentials: the SSO login has expired or was never done; run: aws sso login --profile dev`
		if run.Unresolved != want {
			t.Fatalf("unresolved %q, want %q", run.Unresolved, want)
		}
	})
	t.Run("nothing chosen", func(t *testing.T) {
		run := resolveRunContext(context.Background(), failing(contextSourcesFor("")), plan, "")
		if run.Unresolved != "no AWS credentials found" {
			t.Fatalf("unresolved %q", run.Unresolved)
		}
	})
	t.Run("the provider's profile wins", func(t *testing.T) {
		sources := failing(contextSourcesFor(""))
		sources.EnvProfile = func() (string, string) { return "dev", "AWS_PROFILE" }
		run := resolveRunContext(context.Background(), sources, profilePlan(`{"constant_value":"prod"}`, `"region":{"value":"eu-west-1"}`), "")
		if !strings.HasPrefix(run.Unresolved, `AWS profile "prod" (from provider block) has no usable credentials: `) {
			t.Fatalf("unresolved %q", run.Unresolved)
		}
	})
	t.Run("config that cannot be loaded", func(t *testing.T) {
		sources := contextSourcesFor("")
		sources.EnvProfile = func() (string, string) { return "dev", "AWS_PROFILE" }
		sources.LoadConfig = func(context.Context, string) (sdk.Config, error) {
			return sdk.Config{}, errors.New("failed to get shared config profile, dev")
		}
		run := resolveRunContext(context.Background(), sources, plan, "")
		const want = `AWS profile "dev" (from AWS_PROFILE) could not be loaded: failed to get shared config profile, dev`
		if run.Unresolved != want || run.Identity.Unresolved != want {
			t.Fatalf("unresolved %q, identity %q; want %q", run.Unresolved, run.Identity.Unresolved, want)
		}
	})
}
