package aws

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/tfpreflight/tfpreflight/internal/checks/dependencies"
	"github.com/tfpreflight/tfpreflight/internal/plan"
)

// profilePlan is the plan Terraform writes for a provider block with a region
// and the given profile expression, and the given recorded variables.
func profilePlan(profile, variables string) []byte {
	region := `{"constant_value":"eu-west-1"}`
	if profile != "" {
		region += `,"profile":` + profile
	}
	data := string(contextPlanRegion(region))
	return []byte(replaceOnce(data, `"variables":{"region":{"value":"eu-west-1"}}`, `"variables":{`+variables+`}`))
}

func replaceOnce(text, old, new string) string {
	for i := 0; i+len(old) <= len(text); i++ {
		if text[i:i+len(old)] == old {
			return text[:i] + new + text[i+len(old):]
		}
	}
	panic("replaceOnce: " + old + " not found")
}

const onlyPlain = "; only a literal, a bare variable, or a local set to a plain string can be resolved"

// The provider's profile is resolved the way its region is, and the SDK
// configuration is loaded from it, so the inspection credentials are the ones
// Terraform applies with.
func TestProviderProfileLoadsTheConfig(t *testing.T) {
	const recorded = `"region":{"value":"eu-west-1"},"aws_profile":{"value":"example"}`
	for name, tc := range map[string]profileCase{
		"no profile": {
			providerBlock: ``, wantLoaded: "",
		},
		"literal": {
			providerBlock: `profile = "prod"`, profile: `{"constant_value":"prod"}`, variables: recorded,
			wantLoaded: "prod", wantProfile: "prod", wantSource: "provider block",
		},
		"variable with a value": {
			providerBlock: `profile = var.aws_profile`, profile: `{"references":["var.aws_profile"]}`, variables: recorded,
			wantLoaded: "example", wantProfile: "example", wantSource: "var.aws_profile",
		},
		"local set to a plain string": {
			providerBlock: "profile = local.profile\n}\nlocals {\n  profile = \"from-local\"", profile: `{"references":["local.profile"]}`, variables: recorded,
			wantLoaded: "from-local", wantProfile: "from-local", wantSource: "local.profile",
		},
		// Terraform sets no profile for a null or empty one: the provider
		// takes the environment's credentials, as when none is written.
		"variable recorded as null": {
			providerBlock: `profile = var.aws_profile`, profile: `{"references":["var.aws_profile"]}`, variables: `"region":{"value":"eu-west-1"},"aws_profile":{"value":null}`,
			wantLoaded: "",
		},
		"variable recorded as empty": {
			providerBlock: `profile = var.aws_profile`, profile: `{"references":["var.aws_profile"]}`, variables: `"region":{"value":"eu-west-1"},"aws_profile":{"value":""}`,
			wantLoaded: "",
		},
		"variable recorded as a number": {
			providerBlock: `profile = var.aws_profile`, profile: `{"references":["var.aws_profile"]}`, variables: `"region":{"value":"eu-west-1"},"aws_profile":{"value":7}`,
			wantReason: "provider profile is var.aws_profile but its value in the plan is not a non-empty string",
		},
		"variable missing from the plan": {
			providerBlock: `profile = var.other`, profile: `{"references":["var.other"]}`, variables: recorded,
			wantReason: "provider profile is var.other but the plan records no value for it",
		},
		"function of a variable": {
			providerBlock: `profile = format("%s", var.aws_profile)`, profile: `{"references":["var.aws_profile"]}`, variables: recorded,
			wantReason: "provider profile is an expression of var.aws_profile, not the variable itself" + onlyPlain,
		},
		"local built from a variable": {
			providerBlock: "profile = local.profile\n}\nlocals {\n  profile = var.aws_profile", profile: `{"references":["local.profile"]}`, variables: recorded,
			wantReason: "provider profile is computed from local.profile" + onlyPlain,
		},
		"conditional": {
			providerBlock: `profile = var.prod ? "a" : var.aws_profile`, profile: `{"references":["var.prod","var.aws_profile"]}`, variables: recorded,
			wantReason: "provider profile is computed from var.prod, var.aws_profile" + onlyPlain,
		},
		"function of literals": {
			providerBlock: `profile = lower("PROD")`, profile: `{}`, variables: recorded,
			wantReason: "provider profile is an expression tfpreflight cannot evaluate" + onlyPlain,
		},
	} {
		t.Run(name, func(t *testing.T) {
			run, loaded := runWithProfile(t, tc)
			assertProfileRun(t, tc, run, loaded)
		})
	}
}

// profileCase is one way of writing the provider's profile, and what the run
// should make of it.
type profileCase struct {
	providerBlock string // the provider block's attributes, in main.tf
	profile       string // the profile expression in the plan
	variables     string
	wantLoaded    string // the profile the SDK configuration was loaded with
	wantProfile   string
	wantSource    string
	wantReason    string
}

// runWithProfile resolves a run for the case, and says which profile the SDK
// configuration was loaded with.
func runWithProfile(t *testing.T, tc profileCase) (run RunContext, loaded string) {
	t.Helper()
	dir := t.TempDir()
	source := "provider \"aws\" {\n  region = \"eu-west-1\"\n  " + tc.providerBlock + "\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded = "not loaded"
	sources := contextSourcesFor("arn:aws:iam::" + contextTestAccount + ":user/inspector")
	sources.LoadConfig = func(_ context.Context, profile string) (sdk.Config, error) {
		loaded = profile
		return sdk.Config{Region: "us-east-1"}, nil
	}
	sources.ProfileVariable = func() (string, bool, error) { return plan.ProviderVariable(dir, "", "profile") }
	sources.ProfileLocal = func() (string, string, bool, error) { return plan.ProviderLocal(dir, "", "profile") }
	return resolveRunContext(context.Background(), sources, profilePlan(tc.profile, tc.variables), ""), loaded
}

func assertProfileRun(t *testing.T, tc profileCase, run RunContext, loaded string) {
	t.Helper()
	if run.Unresolved != tc.wantReason {
		t.Fatalf("unresolved %q, want %q", run.Unresolved, tc.wantReason)
	}
	if loaded != tc.wantLoaded {
		t.Errorf("the SDK configuration was loaded with profile %q, want %q", loaded, tc.wantLoaded)
	}
	if tc.wantReason != "" {
		return
	}
	if run.Profile != tc.wantProfile || run.ProfileSource != tc.wantSource {
		t.Errorf("profile %q from %q, want %q from %q", run.Profile, run.ProfileSource, tc.wantProfile, tc.wantSource)
	}
	if run.Region != "eu-west-1" || run.Account != contextTestAccount {
		t.Errorf("scope region %q account %q", run.Region, run.Account)
	}
}

// Without the provider block's source a variable profile cannot be confirmed
// to be used as-is, so nothing is guessed.
func TestProviderProfileVariableNeedsTheSource(t *testing.T) {
	sources := contextSourcesFor("arn:aws:iam::" + contextTestAccount + ":user/inspector")
	run := resolveRunContext(context.Background(), sources, profilePlan(`{"references":["var.aws_profile"]}`, `"region":{"value":"eu-west-1"},"aws_profile":{"value":"example"}`), "")
	const want = "provider profile references var.aws_profile but the provider block source is unavailable to confirm it is used as-is"
	if run.Unresolved != want {
		t.Fatalf("unresolved %q, want %q", run.Unresolved, want)
	}
}

// A profile the SDK cannot load, or one with no credentials, is reported by
// name, with where the run read it from.
func TestProviderProfileFailuresNameTheProfile(t *testing.T) {
	plan := profilePlan(`{"references":["var.aws_profile"]}`, `"region":{"value":"eu-west-1"},"aws_profile":{"value":"example"}`)
	named := func(sources contextSources) contextSources {
		sources.ProfileVariable = func() (string, bool, error) { return "aws_profile", true, nil }
		return sources
	}
	t.Run("profile missing from the AWS config", func(t *testing.T) {
		sources := named(contextSourcesFor("arn:aws:iam::" + contextTestAccount + ":user/inspector"))
		sources.LoadConfig = func(context.Context, string) (sdk.Config, error) {
			return sdk.Config{}, errors.New("failed to get shared config profile, example")
		}
		run := resolveRunContext(context.Background(), sources, plan, "")
		const want = `AWS profile "example" (from var.aws_profile) could not be loaded: failed to get shared config profile, example`
		if run.Unresolved != want || run.Identity.Unresolved != want {
			t.Fatalf("unresolved %q, identity %q; want %q", run.Unresolved, run.Identity.Unresolved, want)
		}
	})
	t.Run("profile without credentials", func(t *testing.T) {
		sources := named(contextSourcesFor(""))
		sources.Credentials = func(context.Context, sdk.Config) error { return errors.New("no credentials") }
		run := resolveRunContext(context.Background(), sources, plan, "")
		const want = `no AWS credentials found for profile "example" (from var.aws_profile)`
		if run.Unresolved != want {
			t.Fatalf("unresolved %q, want %q", run.Unresolved, want)
		}
	})
	t.Run("environment credentials keep the old wording", func(t *testing.T) {
		sources := contextSourcesFor("")
		sources.Credentials = func(context.Context, sdk.Config) error { return errors.New("no credentials") }
		run := resolveRunContext(context.Background(), sources, profilePlan("", `"region":{"value":"eu-west-1"}`), "")
		if run.Unresolved != "no AWS credentials found" {
			t.Fatalf("unresolved %q", run.Unresolved)
		}
	})
}

// An unresolved profile is reported before anything that was learned with the
// wrong credentials: they may not be the provider's.
func TestUnresolvedProfileComesFirst(t *testing.T) {
	in := scopeInputs{
		Provider:      providerWithProfileReferences("var.missing"),
		NoCredentials: true,
		Profile:       "default",
	}
	got := resolveScope(in).Reason
	const want = "provider profile references var.missing but the provider block source is unavailable to confirm it is used as-is"
	if got != want {
		t.Fatalf("reason %q, want %q", got, want)
	}
}

func providerWithProfileReferences(references ...string) dependencies.ProviderContext {
	return dependencies.ProviderContext{
		RegionKind: dependencies.RegionLiteral, Region: "eu-west-1",
		ProfileKind: dependencies.ArgumentReferences, ProfileReferences: references,
	}
}
