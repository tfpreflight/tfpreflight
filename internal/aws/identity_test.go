package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/rules/model"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type fakeSTSClient struct{ arn string }

func (f fakeSTSClient) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{Arn: &f.arn}, nil
}

func TestDiscoverAWSContextUsesExplicitPrincipal(t *testing.T) {
	sources := contextSources{
		LoadConfig: func(context.Context, string) (sdk.Config, error) { return sdk.Config{}, nil },
		CallerIdentity: func(ctx context.Context, _ sdk.Config) (string, error) {
			return callerIdentity(ctx, fakeSTSClient{arn: "arn:aws:iam::123:user/inspector"})
		},
		Profile: func() string { return "default" },
	}
	context := resolveRunContext(context.Background(), sources, nil, "arn:aws:iam::123:role/terraform-ci").Identity
	if !context.ApplyIdentityKnown || context.ApplyIdentity != "arn:aws:iam::123:role/terraform-ci" || context.InspectionIdentity != "arn:aws:iam::123:user/inspector" {
		t.Fatalf("unexpected context: %#v", context)
	}
}

// assumeRolePlan is the context plan with the provider assuming a role.
func assumeRolePlan(assumeRole string) []byte {
	return []byte(strings.Replace(string(contextPlanRegion(`{"constant_value":"eu-west-1"}`)),
		`"expressions":{"region":{"constant_value":"eu-west-1"}}`,
		`"expressions":{"region":{"constant_value":"eu-west-1"},"assume_role":[`+assumeRole+`]}`, 1))
}

type assumeCall struct{ role, externalID string }

func identitySources(inspection string, assume func(role string) error, calls *[]assumeCall) contextSources {
	sources := contextSourcesFor(inspection)
	sources.AssumeRoleVariable = func() (string, bool, error) { return "deploy_role", true, nil }
	sources.RoleARN = func(_ context.Context, _ sdk.Config, name string) (string, error) {
		if name == "terraform" {
			return "arn:aws:iam::123456789012:role/ci/terraform", nil
		}
		return "", errors.New("AccessDenied: iam:GetRole")
	}
	sources.AssumeRole = func(_ context.Context, config sdk.Config, role, externalID string) (sdk.Config, error) {
		*calls = append(*calls, assumeCall{role, externalID})
		if err := assume(role); err != nil {
			return config, err
		}
		config.AppID = "assumed:" + role
		return config, nil
	}
	return sources
}

func TestApplyIdentityPaths(t *testing.T) {
	const deploy = "arn:aws:iam::999999999999:role/deploy"
	ok := func(string) error { return nil }
	for _, c := range []identityPathCase{
		{
			name: "--principal wins", inspection: "arn:aws:iam::123456789012:user/inspector", principal: "arn:aws:iam::123456789012:role/ci",
			plan: contextPlan("eu-west-1"), identity: "arn:aws:iam::123456789012:role/ci", source: IdentityFromFlag, account: "123456789012",
		},
		{
			name: "assume_role literal", inspection: "arn:aws:iam::123456789012:user/inspector",
			plan:     assumeRolePlan(`{"role_arn":{"constant_value":"` + deploy + `"},"external_id":{"constant_value":"x-1"}}`),
			identity: deploy, source: IdentityFromAssumeRole, account: "999999999999", assumed: deploy, externalID: "x-1",
		},
		{
			name: "assume_role var", inspection: "arn:aws:iam::123456789012:user/inspector",
			plan:     []byte(strings.Replace(string(assumeRolePlan(`{"role_arn":{"references":["var.deploy_role"]}}`)), `"variables":{"region":{"value":"eu-west-1"}}`, `"variables":{"region":{"value":"eu-west-1"},"deploy_role":{"value":"`+deploy+`"}}`, 1)),
			identity: deploy, source: IdentityFromAssumeRole + " (var.deploy_role)", account: "999999999999", assumed: deploy,
		},
		{
			name: "assume_role unresolvable", inspection: "arn:aws:iam::123456789012:user/inspector",
			plan: assumeRolePlan(`{"role_arn":{"references":["local.role"]}}`), note: "--principal", account: "123456789012", inspectionGap: "cannot name",
		},
		{
			name: "assume_role fails", inspection: "arn:aws:iam::123456789012:user/inspector",
			plan: assumeRolePlan(`{"role_arn":{"constant_value":"` + deploy + `"}}`), assume: func(string) error { return errors.New("AccessDenied: not authorized to perform sts:AssumeRole") },
			identity: deploy, source: IdentityFromAssumeRole, account: "999999999999", inspectionGap: "could not assume",
		},
		{
			name: "inspection IAM user", inspection: "arn:aws:iam::123456789012:user/inspector",
			plan: contextPlan("eu-west-1"), identity: "arn:aws:iam::123456789012:user/inspector", source: IdentityFromInspection, account: "123456789012",
		},
		{
			name: "assumed-role session", inspection: "arn:aws:sts::123456789012:assumed-role/terraform/ci-run",
			plan: contextPlan("eu-west-1"), identity: "arn:aws:iam::123456789012:role/ci/terraform", source: IdentityFromSession, account: "123456789012",
		},
		{
			name: "SSO session without iam:GetRole", inspection: "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Admin_0123abcd/someone@example.com",
			plan: contextPlan("eu-west-1"), identity: "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_0123abcd", source: IdentityFromSession, account: "123456789012",
		},
		{
			name: "federated user", inspection: "arn:aws:sts::123456789012:federated-user/someone",
			plan: contextPlan("eu-west-1"), note: "--principal", account: "123456789012",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			assume := c.assume
			if assume == nil {
				assume = ok
			}
			var calls []assumeCall
			run := resolveRunContext(context.Background(), identitySources(c.inspection, assume, &calls), c.plan, c.principal)
			assertApplyIdentity(t, c, run)
			assertInspectionIdentity(t, c, run, calls)
		})
	}
}

type identityPathCase struct {
	name, inspection, principal string
	plan                        []byte
	assume                      func(string) error
	identity, source            string
	note                        string // a substring the note must have, when the identity is unknown
	account                     string
	assumed, inspectionGap      string
	externalID                  string // the external_id the single assume call must carry
}

// assertApplyIdentity checks who the run says applies, and that the account
// resolved.
func assertApplyIdentity(t *testing.T, c identityPathCase, run RunContext) {
	t.Helper()
	id := run.Identity
	if c.identity != "" {
		if !id.ApplyIdentityKnown || id.ApplyIdentity != c.identity || id.ApplyIdentitySource != c.source {
			t.Fatalf("identity %q from %q (known %v), want %q from %q", id.ApplyIdentity, id.ApplyIdentitySource, id.ApplyIdentityKnown, c.identity, c.source)
		}
	} else if id.ApplyIdentityKnown || !strings.Contains(id.ApplyIdentityNote, c.note) {
		t.Fatalf("identity should be unknown with a note naming %q: %+v", c.note, id)
	}
	if run.Account != c.account || !run.Resolved() {
		t.Fatalf("account %q (unresolved %q), want %q", run.Account, run.Unresolved, c.account)
	}
}

// assertInspectionIdentity checks which role inspection assumed, how, and
// whether inspection is available.
func assertInspectionIdentity(t *testing.T, c identityPathCase, run RunContext, calls []assumeCall) {
	t.Helper()
	if c.assumed != "" {
		if run.Identity.AssumedRole != c.assumed || run.Config.AppID != "assumed:"+c.assumed || !run.Inspects() {
			t.Fatalf("inspection did not assume %s: %+v", c.assumed, run.Identity)
		}
	}
	if c.externalID != "" && (len(calls) != 1 || calls[0].externalID != c.externalID) {
		t.Fatalf("assume calls %+v", calls)
	}
	if c.inspectionGap != "" && (run.Inspects() || !strings.Contains(run.InspectionUnavailable, c.inspectionGap)) {
		t.Fatalf("inspection should be unavailable (%q): %q", c.inspectionGap, run.InspectionUnavailable)
	}
	if c.inspectionGap == "" && !run.Inspects() {
		t.Fatalf("inspection unavailable: %q", run.InspectionUnavailable)
	}
}

// A role that cannot be assumed leaves conflicts and quotas partial with the
// reason; permissions are still simulated, and the run completes.
func TestAssumeRoleFailureIsPartialNotFatal(t *testing.T) {
	var calls []assumeCall
	sources := identitySources("arn:aws:iam::123456789012:user/inspector", func(string) error { return errors.New("AccessDenied") }, &calls)
	plan := assumeRolePlan(`{"role_arn":{"constant_value":"arn:aws:iam::999999999999:role/deploy"}}`)
	run := resolveRunContext(context.Background(), sources, plan, "")
	recorder := &contextRecorder{}
	result, err := runChecks(context.Background(), recordingChecks(recorder), run, contextChanges(), testProviderVersion, plan)
	if err != nil {
		t.Fatal(err)
	}
	called := map[string]bool{}
	for _, s := range recorder.calls {
		called[s.check] = true
	}
	if called["conflicts"] || called["quotas"] || !called["permissions"] {
		t.Fatalf("checks run: %v", called)
	}
	for _, resource := range result.Coverage.Resources {
		if resource.Resource == "aws_s3_bucket.test" && (resource.Conflicts != model.CheckPartialAWSContext || !strings.Contains(resource.UnresolvedAWSContext, "could not assume")) {
			t.Fatalf("coverage %+v", resource)
		}
		if resource.Permissions == model.CheckPartialAWSContext {
			t.Fatalf("permissions were made partial by the role: %+v", resource)
		}
	}
}
