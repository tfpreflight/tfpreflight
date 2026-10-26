package permissions

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// The fix for an explicit deny names where IAM says the deny is: an
// organization's SCPs, the role's permissions boundary, or the role itself.
func TestExplicitDenyFixNamesWhereTheDenyIs(t *testing.T) {
	for want, evaluation := range map[string]types.EvaluationResult{
		`Fix: remove or narrow the deny on role "deploy".`: {},
		"Fix: remove or narrow the deny in your organization's service control policies.": {
			OrganizationsDecisionDetail: &types.OrganizationsDecisionDetail{AllowedByOrganizations: false},
		},
		`Fix: remove or narrow the deny in the permissions boundary of role "deploy".`: {
			OrganizationsDecisionDetail:       &types.OrganizationsDecisionDetail{AllowedByOrganizations: true},
			PermissionsBoundaryDecisionDetail: &types.PermissionsBoundaryDecisionDetail{AllowedByPermissionsBoundary: false},
		},
	} {
		if got := "Fix: remove or narrow the deny " + denySource(evaluation, principal) + "."; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestPrincipalLabel(t *testing.T) {
	for arn, want := range map[string]string{
		"arn:aws:iam::123456789012:role/deploy":                 `role "deploy"`,
		"arn:aws:iam::123456789012:role/ci/deploy":              `role "deploy"`,
		"arn:aws:sts::123456789012:assumed-role/deploy/session": `role "deploy"`,
		"arn:aws:iam::123456789012:user/alice":                  `user "alice"`,
		"arn:aws:iam::123456789012:federated-user/odd":          "the apply identity",
		"": "the apply identity",
		"arn:aws-us-gov:iam::123456789012:role/service-role/terraform": `role "terraform"`,
	} {
		if got := principalLabel(arn); got != want {
			t.Errorf("%q: got %q, want %q", arn, got, want)
		}
	}
}

// Every permission finding, blocking or demoted, has a one-sentence brief and
// one Fix: or Check: line; a demoted one says "may not" and why to check.
func TestEveryFindingHasABrief(t *testing.T) {
	deny := func(decision types.PolicyEvaluationDecisionType, missing ...string) *policyIAM {
		return &policyIAM{decide: func(*iam.SimulatePrincipalPolicyInput) (types.PolicyEvaluationDecisionType, []string) {
			return decision, missing
		}}
	}
	required := lambdaCreate(map[string]any{"function_name": "api"}, nil, "verified")
	conditional := required
	conditional.operation.Certainty = packs.CertaintyConditional
	unknown := required
	unknown.operation.Certainty = packs.CertaintyUnknown
	cases := []struct {
		name        string
		client      *policyIAM
		requirement plannedPermission
		next        string
	}{
		{"implicit verified", deny(types.PolicyEvaluationDecisionTypeImplicitDeny), required, `Fix: allow lambda:CreateFunction for role "deploy".`},
		{"implicit generated", deny(types.PolicyEvaluationDecisionTypeImplicitDeny), lambdaCreate(map[string]any{"function_name": "api"}, nil, "generated"), "Check: this rule comes from the provider's source and is not yet verified against AWS."},
		{"explicit", deny(types.PolicyEvaluationDecisionTypeExplicitDeny), required, `Fix: remove or narrow the deny on role "deploy".`},
		{"explicit missing context", deny(types.PolicyEvaluationDecisionTypeExplicitDeny, "aws:RequestTag/team"), required, "Check: the deny depends on request details the plan does not give (aws:RequestTag/team)."},
		{"explicit conditional", deny(types.PolicyEvaluationDecisionTypeExplicitDeny), conditional, "Check: the provider makes this call only in some cases."},
		{"explicit unknown", deny(types.PolicyEvaluationDecisionTypeExplicitDeny), unknown, "Check: the rules do not say whether the provider always makes this call."},
	}
	for _, c := range cases {
		result := simulatePermissions(context.Background(), c.client, principal, testScope, []plannedPermission{c.requirement})
		if len(result.Findings) != 1 {
			t.Fatalf("%s: findings = %+v", c.name, result.Findings)
		}
		f := result.Findings[0]
		assertBrief(t, f)
		if f.Next != c.next {
			t.Errorf("%s: next = %q, want %q", c.name, f.Next, c.next)
		}
		if wantVerb := map[bool]string{true: "is not allowed", false: "may not be allowed"}[f.Severity == model.SeverityError]; !strings.Contains(f.Brief, wantVerb) {
			t.Errorf("%s: brief %q lacks %q", c.name, f.Brief, wantVerb)
		}
	}
	builtOnly := &policyIAM{decide: func(input *iam.SimulatePrincipalPolicyInput) (types.PolicyEvaluationDecisionType, []string) {
		if input.ResourceArns[0] == "*" {
			return types.PolicyEvaluationDecisionTypeAllowed, nil
		}
		return types.PolicyEvaluationDecisionTypeImplicitDeny, nil
	}}
	result := simulatePermissions(context.Background(), builtOnly, principal, testScope, []plannedPermission{required})
	if f := result.Findings[0]; f.Next != "Check: IAM denies it only for the resource ARN tfpreflight built, not for every resource." {
		t.Errorf("built ARN: next = %q", f.Next)
	}
	partial := PartialFindings(Unchecked{"aws_lambda_function.api": "lambda:CreateFunction may be denied: x; iam:PassRole may be denied: y"})[0]
	if partial.Brief != "IAM did not clearly allow lambda:CreateFunction, iam:PassRole for the apply identity." {
		t.Errorf("partial brief = %q", partial.Brief)
	}
	for _, f := range []model.Finding{
		partial,
		UncheckedFindings(Unchecked{"aws_lambda_function.api": uncheckedReason("lambda:CreateFunction", errors.New("boom"))})[0],
	} {
		assertBrief(t, f)
	}
}

// assertBrief checks a finding's default-output text: one sentence, then one
// line starting "Fix:" or "Check:".
func assertBrief(t *testing.T, finding model.Finding) {
	t.Helper()
	brief, next := finding.Brief, finding.Next
	if brief == "" || !strings.HasSuffix(brief, ".") || strings.ContainsAny(brief, "\n") || strings.Count(strings.TrimSuffix(brief, "."), ". ") > 0 {
		t.Errorf("%s: brief %q is not one sentence", finding.ID, brief)
	}
	if !strings.HasPrefix(next, "Fix: ") && !strings.HasPrefix(next, "Check: ") || strings.Contains(next, "\n") {
		t.Errorf("%s: next %q is not one Fix: or Check: line", finding.ID, next)
	}
}

// The warning the README and docs/output.md show is the one the 6.64.0 rules
// really give for a public access block on an existing bucket, when IAM does
// not allow the call.
func TestDocumentedWarningIsReal(t *testing.T) {
	pack, loaded, err := packs.LoadRuntimePack("6.64.0")
	if err != nil || !loaded {
		t.Fatalf("load 6.64.0 rules: loaded=%t err=%v", loaded, err)
	}
	change := model.PlannedChange{
		Address: "aws_s3_bucket_public_access_block.logs", ResourceType: "aws_s3_bucket_public_access_block",
		ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate, After: map[string]any{"bucket": "acme-logs"},
	}
	var requirement plannedPermission
	for _, candidate := range requiredPermissions(packs.ResolveRules(pack, []model.PlannedChange{change})) {
		if candidate.operation.Permission == "s3:PutBucketPublicAccessBlock" {
			requirement = candidate
		}
	}
	client := &fakeIAMSimulator{decision: types.PolicyEvaluationDecisionTypeImplicitDeny}
	result := simulatePermissions(context.Background(), client, principal, testScope, []plannedPermission{requirement})
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %+v", result.Findings)
	}
	f := result.Findings[0]
	if f.Severity != model.SeverityWarning || f.Brief != "The apply role may not be allowed to run s3:PutBucketPublicAccessBlock." ||
		f.Next != "Check: this rule comes from the provider's source and is not yet verified against AWS." {
		t.Fatalf("severity %s, brief %q, next %q", f.Severity, f.Brief, f.Next)
	}
}

// The full output's problem names the principal's kind as the brief does: an
// assumed-role session is its role, and an ARN that says neither is an
// identity.
func TestProblemNamesPrincipalKind(t *testing.T) {
	requirement := lambdaCreate(map[string]any{"function_name": "api"}, nil, "verified")
	for arn, want := range map[string]string{
		"arn:aws:iam::123456789012:role/deploy":                 "The deployment role does not have lambda:CreateFunction.",
		"arn:aws:sts::123456789012:assumed-role/deploy/session": "The deployment role does not have lambda:CreateFunction.",
		"arn:aws:iam::123456789012:user/ci":                     "The deployment user does not have lambda:CreateFunction.",
		"":                                                      "The deployment identity does not have lambda:CreateFunction.",
	} {
		if got := permissionDeniedFinding(requirement, arn, "implicitDeny", "*").Problem; got != want {
			t.Errorf("%q: %q, want %q", arn, got, want)
		}
	}
}
