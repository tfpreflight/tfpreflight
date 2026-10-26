package aws

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/tfpreflight/tfpreflight/internal/checks/conflicts"
	"github.com/tfpreflight/tfpreflight/internal/checks/dependencies"
	"github.com/tfpreflight/tfpreflight/internal/checks/permissions"
	"github.com/tfpreflight/tfpreflight/internal/checks/quotas"
	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/internal/plan"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

const contextTestAccount = "123456789012"

// contextPlan targets planRegion through the default provider, or leaves the
// region to a variable when planRegion is empty. aws_subnet.test names an
// existing VPC by literal id, so the dependency check has to look it up.
func contextPlan(planRegion string) []byte {
	region := `{"references":["var.region"]}`
	if planRegion != "" {
		region = `{"constant_value":"` + planRegion + `"}`
	}
	return contextPlanRegion(region)
}

// contextPlanRegion builds the plan with the provider's region expression as
// Terraform writes it, or with no region at all when region is empty. The
// plan records var.region = "eu-west-1".
func contextPlanRegion(region string) []byte {
	expressions := `{}`
	if region != "" {
		expressions = `{"region":` + region + `}`
	}
	return []byte(`{"format_version":"1.2","variables":{"region":{"value":"eu-west-1"}},"configuration":{"provider_config":{"aws":{"full_name":"registry.terraform.io/hashicorp/aws","expressions":` + expressions + `}},"root_module":{"resources":[{"mode":"managed","type":"aws_subnet","name":"test","provider_config_key":"aws","expressions":{"vpc_id":{"constant_value":"vpc-0123456789abcdef0"}}}]}},"resource_changes":[{"address":"aws_subnet.test","mode":"managed","type":"aws_subnet","name":"test","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"after":{"vpc_id":"vpc-0123456789abcdef0","cidr_block":"10.0.1.0/24"},"after_unknown":{}}},{"address":"aws_s3_bucket.test","mode":"managed","type":"aws_s3_bucket","name":"test","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"after":{"bucket":"context-test"},"after_unknown":{}}}]}`)
}

func contextChanges() []model.PlannedChange {
	return []model.PlannedChange{
		{Address: "aws_subnet.test", ResourceType: "aws_subnet", ProviderName: "registry.terraform.io/hashicorp/aws", ProviderConfigKey: "aws", Action: model.ActionCreate, After: map[string]any{"vpc_id": "vpc-0123456789abcdef0", "cidr_block": "10.0.1.0/24"}},
		{Address: "aws_s3_bucket.test", ResourceType: "aws_s3_bucket", ProviderName: "registry.terraform.io/hashicorp/aws", ProviderConfigKey: "aws", Action: model.ActionCreate, After: map[string]any{"bucket": "context-test"}},
	}
}

// The SDK region deliberately differs from the plan's, so a check that read
// the SDK region instead of the run context would report the wrong one.
func contextSourcesFor(identity string) contextSources {
	return contextSources{
		LoadConfig: func(context.Context) (sdk.Config, error) { return sdk.Config{Region: "us-east-1"}, nil },
		CallerIdentity: func(context.Context, sdk.Config) (string, error) {
			if identity == "" {
				return "", errors.New("no credentials")
			}
			return identity, nil
		},
		Profile: func() string { return "default" },
	}
}

// seen is what one check was given: the region its clients would call and the
// account it believes it is in.
type seen struct{ check, configRegion, region, account string }

type contextRecorder struct {
	mu    sync.Mutex
	calls []seen
}

func (r *contextRecorder) record(check string, run RunContext) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, seen{check, run.Config.Region, run.Region, run.Account})
}

// Exists records the scope the dependency engine asks in. It is the real
// engine, reached through DependencyRuntime exactly as production reaches it.
func (r *contextRecorder) Exists(_ context.Context, _ dependencies.Lookup, scope dependencies.Scope, _ string) (dependencies.Existence, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, seen{"dependencies", scope.Region, scope.Region, scope.Account})
	return dependencies.Exists, ""
}

func recordingChecks(recorder *contextRecorder) awsChecks {
	return awsChecks{
		Conflicts: func(_ context.Context, run RunContext, _ []packs.ResolvedRule) ([]model.Finding, error) {
			recorder.record("conflicts", run)
			return nil, nil
		},
		IdentityConflicts: func(_ context.Context, run RunContext, _ string, _ []model.PlannedChange) ([]model.Finding, []conflicts.Coverage, error) {
			recorder.record("identity-conflicts", run)
			return nil, nil, nil
		},
		EC2VCPU: func(_ context.Context, run RunContext, _ []packs.ResolvedRule) ([]model.Finding, error) {
			recorder.record("ec2-vcpu", run)
			return nil, nil
		},
		Quotas: func(_ context.Context, run RunContext, _ []model.PlannedChange, _ map[string]quotas.Rule) []model.Finding {
			recorder.record("quotas", run)
			return nil
		},
		Permissions: func(_ context.Context, run RunContext, _ []packs.ResolvedRule) permissions.Result {
			recorder.record("permissions", run)
			return permissions.Result{}
		},
		Dependencies: func(ctx context.Context, run RunContext, plan []byte, version string) (dependencyOutcome, error) {
			results, coverage, err := DependencyRuntime(ctx, plan, version, run.Config, run.Identity.InspectionIdentity, recorder)
			return dependencyOutcome{Results: results, Coverage: coverage}, err
		},
	}
}

// One run, one account, one region: every check that calls AWS is given the
// same scope, and it is the region the plan applies to, not the SDK's.
func TestEveryCheckGetsTheSameAccountAndRegion(t *testing.T) {
	plan := contextPlan("eu-west-1")
	run := resolveRunContext(context.Background(), contextSourcesFor("arn:aws:iam::"+contextTestAccount+":user/inspector"), plan, "arn:aws:iam::"+contextTestAccount+":role/deployer")
	if !run.Resolved() {
		t.Fatalf("context unresolved: %s", run.Unresolved)
	}
	if run.Region != "eu-west-1" || run.Config.Region != "eu-west-1" || run.Account != contextTestAccount {
		t.Fatalf("run context = region %q (config %q), account %q; want the plan's eu-west-1 in %s", run.Region, run.Config.Region, run.Account, contextTestAccount)
	}
	recorder := &contextRecorder{}
	if _, err := runChecks(context.Background(), recordingChecks(recorder), run, contextChanges(), testProviderVersion, plan); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"conflicts": true, "identity-conflicts": true, "ec2-vcpu": true, "quotas": true, "permissions": true, "dependencies": true}
	for _, call := range recorder.calls {
		delete(want, call.check)
		if call.configRegion != "eu-west-1" || call.region != "eu-west-1" || call.account != contextTestAccount {
			t.Errorf("%s ran in region %q (clients %q), account %q; every check must use eu-west-1 in %s", call.check, call.region, call.configRegion, call.account, contextTestAccount)
		}
	}
	for check := range want {
		t.Errorf("%s was never called, so this test proves nothing about it", check)
	}
}

// When the account or region cannot be decided, nothing calls AWS, and every
// AWS check that applies says so instead of answering for somewhere else.
func TestUnresolvedContextMakesEveryAWSCheckPartial(t *testing.T) {
	for name, tc := range map[string]struct {
		plan     []byte
		identity string
		reason   string
	}{
		"region from a local":    {contextPlanRegion(`{"references":["local.region"]}`), "arn:aws:iam::" + contextTestAccount + ":user/inspector", "provider region is computed from local.region; only a literal, a bare variable, or a local set to a plain string can be resolved"},
		"no inspection identity": {contextPlan("eu-west-1"), "", "inspection account identity unavailable: no credentials"},
	} {
		t.Run(name, func(t *testing.T) {
			run := resolveRunContext(context.Background(), contextSourcesFor(tc.identity), tc.plan, "arn:aws:iam::"+contextTestAccount+":role/deployer")
			if run.Unresolved != tc.reason {
				t.Fatalf("unresolved = %q, want %q", run.Unresolved, tc.reason)
			}
			recorder := &contextRecorder{}
			result, err := runChecks(context.Background(), recordingChecks(recorder), run, contextChanges(), testProviderVersion, tc.plan)
			if err != nil {
				t.Fatal(err)
			}
			if len(recorder.calls) != 0 {
				t.Fatalf("checks reached AWS with an unresolved context: %+v", recorder.calls)
			}
			for _, resource := range result.Coverage.Resources {
				assertNoCheckWithoutContext(t, resource, tc.reason)
			}
			subnet := result.Coverage.Resources[0]
			if subnet.Resource != "aws_subnet.test" || subnet.Permissions != model.CheckPartialAWSContext || subnet.Dependencies != model.CheckPartialDependency {
				t.Fatalf("aws_subnet.test coverage = %+v", subnet)
			}
		})
	}
}

// assertNoCheckWithoutContext requires a resource to carry the unresolved
// reason and no check to claim it ran.
func assertNoCheckWithoutContext(t *testing.T, resource model.ResourceCoverage, reason string) {
	t.Helper()
	if resource.UnresolvedAWSContext != reason {
		t.Errorf("%s: context reason = %q, want %q", resource.Resource, resource.UnresolvedAWSContext, reason)
	}
	for check, status := range map[string]model.CheckStatus{"permissions": resource.Permissions, "conflicts": resource.Conflicts, "quota": resource.Quota, "dependencies": resource.Dependencies} {
		switch status {
		case model.CheckNotApplicable, model.CheckUnsupported, model.CheckUnverifiable, model.CheckNoDependencyRule, model.CheckNoQuotaRule:
			// The check does not apply, or nothing ships for it.
		case model.CheckPartialAWSContext, model.CheckPartialDependency:
		default:
			t.Errorf("%s %s = %s with an unresolved AWS context", resource.Resource, check, status)
		}
	}
}

// The run context and the dependency check refuse for the same reasons, because
// they apply the same rules.
func TestDependencyScopeIsTheRunContext(t *testing.T) {
	inspector := "arn:aws:iam::" + contextTestAccount + ":user/inspector"
	for name, tc := range map[string]struct {
		plan     []byte
		identity string
	}{
		"resolved":               {contextPlan("eu-west-1"), inspector},
		"region from a variable": {contextPlan(""), inspector},
		"no inspection identity": {contextPlan("eu-west-1"), ""},
		"profile differs": {[]byte(strings.Replace(string(contextPlan("eu-west-1")),
			`"region":{"constant_value":"eu-west-1"}`, `"region":{"constant_value":"eu-west-1"},"profile":{"constant_value":"prod"}`, 1)), inspector},
		"account not allowed": {[]byte(strings.Replace(string(contextPlan("eu-west-1")),
			`"region":{"constant_value":"eu-west-1"}`, `"region":{"constant_value":"eu-west-1"},"allowed_account_ids":{"constant_value":["999999999999"]}`, 1)), inspector},
	} {
		t.Run(name, func(t *testing.T) {
			run := resolveRunContext(context.Background(), contextSourcesFor(tc.identity), tc.plan, "")
			recorder := &contextRecorder{}
			results, _, err := DependencyRuntime(context.Background(), tc.plan, testProviderVersion, run.Config, run.Identity.InspectionIdentity, recorder)
			if err != nil {
				t.Fatal(err)
			}
			if run.Resolved() {
				assertLookedUpInRunContext(t, run, recorder)
				return
			}
			assertRefusedUnresolved(t, run, recorder, results)
		})
	}
}

func assertLookedUpInRunContext(t *testing.T, run RunContext, recorder *contextRecorder) {
	t.Helper()
	if len(recorder.calls) != 1 || recorder.calls[0].region != run.Region || recorder.calls[0].account != run.Account {
		t.Fatalf("dependency lookups %+v, run context region %q account %q", recorder.calls, run.Region, run.Account)
	}
}

// assertRefusedUnresolved checks nothing was looked up and a result names
// the run's unresolved reason.
func assertRefusedUnresolved(t *testing.T, run RunContext, recorder *contextRecorder, results []dependencies.Result) {
	t.Helper()
	if len(recorder.calls) != 0 {
		t.Fatalf("dependency check looked up with an unresolved context (%s): %+v", run.Unresolved, recorder.calls)
	}
	// DependencyRuntime decides the scope from the identity alone, without
	// the STS error the run context adds to its reason.
	reason := strings.TrimSuffix(run.Unresolved, ": no credentials")
	refused := false
	for _, result := range results {
		refused = refused || strings.Contains(result.Reason, reason)
	}
	if !refused {
		t.Fatalf("dependency check did not refuse for the run's reason %q: %+v", run.Unresolved, results)
	}
}

// Every check takes its configuration from the run context. A check that loads
// its own would pick up the SDK region again, so only the resolver may.
func TestOnlyTheResolverLoadsAWSConfiguration(t *testing.T) {
	root := ".."
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return err
		}
		if filepath.Base(path) == "context.go" && filepath.Base(filepath.Dir(path)) == "aws" {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			if strings.Trim(spec.Path.Value, `"`) == "github.com/aws/aws-sdk-go-v2/config" {
				t.Errorf("%s imports the AWS SDK config loader; checks must use RunContext.Config", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The region is resolved the way Terraform resolves the provider's, from the
// expression shapes Terraform 1.12 actually writes for each form.
func TestRegionResolvesLikeTerraform(t *testing.T) {
	inspector := "arn:aws:iam::" + contextTestAccount + ":user/inspector"
	for name, tc := range map[string]struct {
		providerBlock string // the provider "aws" block in main.tf
		region        string // the plan's region expression; empty for none
		environment   string // the SDK's region from the environment
		wantRegion    string
		wantSource    string
		wantReason    string
	}{
		"literal": {
			`region = "eu-central-1"`, `{"constant_value":"eu-central-1"}`, "ap-south-1",
			"eu-central-1", "provider block", "",
		},
		"variable with a value": {
			`region = var.region`, `{"references":["var.region"]}`, "ap-south-1",
			"eu-west-1", "var.region", "",
		},
		"variable missing from the plan": {
			`region = var.target`, `{"references":["var.target"]}`, "ap-south-1",
			"", "", "provider region is var.target but the plan records no value for it",
		},
		"no region, environment set": {
			``, ``, "ap-south-1",
			"ap-south-1", "environment", "",
		},
		"no region, environment unset": {
			``, ``, "",
			"", "", "the provider block sets no region and none is set in the environment (AWS_REGION, AWS_DEFAULT_REGION or the profile)",
		},
		"local set to a plain string": {
			"region = local.region\n}\nlocals {\n  region = \"eu-west-3\"", `{"references":["local.region"]}`, "ap-south-1",
			"eu-west-3", "local.region", "",
		},
		"local built from a variable": {
			"region = local.region\n}\nlocals {\n  region = var.region", `{"references":["local.region"]}`, "ap-south-1",
			"", "", "provider region is computed from local.region; only a literal, a bare variable, or a local set to a plain string can be resolved",
		},
		"local defined nowhere": {
			`region = local.region`, `{"references":["local.region"]}`, "ap-south-1",
			"", "", "provider region is computed from local.region; only a literal, a bare variable, or a local set to a plain string can be resolved",
		},
		"function of a local": {
			"region = lower(local.region)\n}\nlocals {\n  region = \"EU-WEST-3\"", `{"references":["local.region"]}`, "ap-south-1",
			"", "", "provider region is computed from local.region; only a literal, a bare variable, or a local set to a plain string can be resolved",
		},
		// format("%s", var.region) and var.region produce the same plan JSON;
		// only the source tells them apart.
		"function of a variable": {
			`region = format("%s", var.region)`, `{"references":["var.region"]}`, "ap-south-1",
			"", "", "provider region is an expression of var.region, not the variable itself; only a literal, a bare variable, or a local set to a plain string can be resolved",
		},
		"function of literals": {
			`region = lower("EU-NORTH-1")`, `{}`, "ap-south-1",
			"", "", "provider region is an expression tfpreflight cannot evaluate; only a literal, a bare variable, or a local set to a plain string can be resolved",
		},
		"conditional": {
			`region = var.prod ? "us-east-1" : var.region`, `{"references":["var.prod","var.region"]}`, "ap-south-1",
			"", "", "provider region is computed from var.prod, var.region; only a literal, a bare variable, or a local set to a plain string can be resolved",
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			source := "provider \"aws\" {\n  " + tc.providerBlock + "\n}\n"
			if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			sources := contextSourcesFor(inspector)
			sources.LoadConfig = func(context.Context) (sdk.Config, error) { return sdk.Config{Region: tc.environment}, nil }
			sources.RegionVariable = func() (string, bool, error) { return plan.RegionVariable(dir) }
			sources.RegionLocal = func() (string, string, bool, error) { return plan.RegionLocal(dir) }
			run := resolveRunContext(context.Background(), sources, contextPlanRegion(tc.region), "")
			if run.Region != tc.wantRegion || run.RegionSource != tc.wantSource || run.Unresolved != tc.wantReason {
				t.Fatalf("region %q from %q, unresolved %q; want %q from %q, unresolved %q",
					run.Region, run.RegionSource, run.Unresolved, tc.wantRegion, tc.wantSource, tc.wantReason)
			}
			if run.Config.Region != tc.wantRegion {
				t.Fatalf("checks would call region %q, want %q", run.Config.Region, tc.wantRegion)
			}
			if run.Identity.Region != tc.wantRegion || run.Identity.RegionSource != tc.wantSource || run.Identity.Unresolved != tc.wantReason {
				t.Fatalf("reported context %+v does not match the decision", run.Identity)
			}
		})
	}
}

// A provider that cannot be reconstructed is refused whatever its region.
func TestRegionDoesNotOverrideProviderRefusals(t *testing.T) {
	inspector := "arn:aws:iam::" + contextTestAccount + ":user/inspector"
	data := []byte(strings.Replace(string(contextPlanRegion(`{"constant_value":"eu-west-1"}`)),
		`"expressions":{"region":`, `"expressions":{"assume_role_with_web_identity":[{}],"region":`, 1))
	run := resolveRunContext(context.Background(), contextSourcesFor(inspector), data, "")
	if run.Resolved() || run.Unresolved != "provider context requires unsupported configuration: assume_role_with_web_identity" {
		t.Fatalf("unresolved = %q", run.Unresolved)
	}
}

// The coverage report carries the resolver's result for the types it checks,
// with a context or without one.
func TestCoverageReportsTheResolversConflictResult(t *testing.T) {
	user := model.PlannedChange{Address: "aws_iam_user.ci", ResourceType: "aws_iam_user", ProviderName: "registry.terraform.io/hashicorp/aws", ProviderConfigKey: "aws", Action: model.ActionCreate, After: map[string]any{"name": "ci-deployer"}}
	changes := append(contextChanges(), user)
	inspector := "arn:aws:iam::" + contextTestAccount + ":user/inspector"
	conflictsOf := func(result Result) model.CheckStatus {
		for _, resource := range result.Coverage.Resources {
			if resource.Resource == user.Address {
				return resource.Conflicts
			}
		}
		t.Fatal("aws_iam_user.ci missing from coverage")
		return ""
	}

	run := resolveRunContext(context.Background(), contextSourcesFor(inspector), contextPlan("eu-west-1"), "")
	checks := recordingChecks(&contextRecorder{})
	checks.IdentityConflicts = func(context.Context, RunContext, string, []model.PlannedChange) ([]model.Finding, []conflicts.Coverage, error) {
		return nil, []conflicts.Coverage{{Resource: user.Address, Status: conflicts.StatusChecked}}, nil
	}
	result, err := runChecks(context.Background(), checks, run, changes, testProviderVersion, contextPlan("eu-west-1"))
	if err != nil {
		t.Fatal(err)
	}
	if got := conflictsOf(result); got != model.CheckChecked {
		t.Fatalf("resolved: aws_iam_user conflicts = %s, want checked", got)
	}

	unresolved := resolveRunContext(context.Background(), contextSourcesFor(""), contextPlan("eu-west-1"), "")
	result, err = runChecks(context.Background(), recordingChecks(&contextRecorder{}), unresolved, changes, testProviderVersion, contextPlan("eu-west-1"))
	if err != nil {
		t.Fatal(err)
	}
	if got := conflictsOf(result); got != model.CheckPartialAWSContext {
		t.Fatalf("unresolved: aws_iam_user conflicts = %s, want %s", got, model.CheckPartialAWSContext)
	}
}

// IAM refusing to simulate is "could not check", not a tool failure: the run
// completes, permissions are partial with the reason, and a blocking finding
// from another check still blocks.
func TestPermissionSimulationFailureDoesNotFailTheRun(t *testing.T) {
	inspector := "arn:aws:iam::" + contextTestAccount + ":user/inspector"
	run := resolveRunContext(context.Background(), contextSourcesFor(inspector), contextPlan("eu-west-1"), "arn:aws:iam::"+contextTestAccount+":role/apply")
	simulations := 0
	run.Config.Retryer = func() sdk.Retryer { return sdk.NopRetryer{} }
	run.Config.Credentials = sdk.CredentialsProviderFunc(func(context.Context) (sdk.Credentials, error) {
		return sdk.Credentials{AccessKeyID: "fake", SecretAccessKey: "fake"}, nil
	})
	run.Config.HTTPClient = dependencyHTTP(func(_ *http.Request) (*http.Response, error) {
		simulations++
		body := `<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>not authorized to perform iam:SimulatePrincipalPolicy</Message></Error></ErrorResponse>`
		return &http.Response{StatusCode: 403, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	recorder := &contextRecorder{}
	checks := recordingChecks(recorder)
	checks.Permissions = productionChecks().Permissions
	checks.Conflicts = func(_ context.Context, run RunContext, _ []packs.ResolvedRule) ([]model.Finding, error) {
		recorder.record("conflicts", run)
		return []model.Finding{{ID: "aws.s3-bucket-conflict", Resource: "aws_s3_bucket.test", Category: "resource-conflict", Severity: model.SeverityError, Confidence: model.ConfidenceHigh}}, nil
	}
	result, err := runChecks(context.Background(), checks, run, contextChanges(), testProviderVersion, contextPlan("eu-west-1"))
	if err != nil {
		t.Fatalf("a failed simulation failed the run: %v", err)
	}
	if simulations != 1 {
		t.Fatalf("%d simulation calls; it must stop at the first failure", simulations)
	}
	partial := 0
	for _, resource := range result.Coverage.Resources {
		if resource.Permissions == model.CheckPartialSimulationUnavailable {
			partial++
			if !strings.Contains(resource.PermissionsUnavailable, "AccessDenied") {
				t.Errorf("%s: reason %q does not say why", resource.Resource, resource.PermissionsUnavailable)
			}
		}
	}
	if partial == 0 {
		t.Fatalf("no resource reports permissions partial: %+v", result.Coverage.Resources)
	}
	blocking := false
	for _, finding := range result.Findings {
		blocking = blocking || (finding.Severity == model.SeverityError && finding.Confidence == model.ConfidenceHigh)
	}
	if !blocking {
		t.Fatal("the other check's blocking finding was lost")
	}
	if len(recorder.calls) < 5 {
		t.Fatalf("other checks did not run: %+v", recorder.calls)
	}
}

// With no credentials at all, STS is not asked, the reason says so plainly, and
// the apply identity note does not suggest --principal, which cannot help.
func TestNoCredentialsSaysSoWithoutSuggestingPrincipal(t *testing.T) {
	sources := contextSourcesFor("arn:aws:iam::" + contextTestAccount + ":user/inspector")
	sources.Credentials = func(context.Context, sdk.Config) error {
		return errors.New("failed to refresh cached credentials, no EC2 IMDS role found")
	}
	sources.CallerIdentity = func(context.Context, sdk.Config) (string, error) {
		t.Fatal("STS was asked without credentials")
		return "", nil
	}
	run := resolveRunContext(context.Background(), sources, contextPlan("eu-west-1"), "")
	if run.Unresolved != "no AWS credentials found" {
		t.Fatalf("unresolved = %q", run.Unresolved)
	}
	if note := run.Identity.ApplyIdentityNote; strings.Contains(note, "--principal") || !strings.Contains(note, "no AWS credentials") {
		t.Fatalf("apply identity note = %q", note)
	}
	if !strings.Contains(run.CredentialsError, "no EC2 IMDS role found") {
		t.Fatalf("the SDK's reason is lost for --debug: %q", run.CredentialsError)
	}
}
