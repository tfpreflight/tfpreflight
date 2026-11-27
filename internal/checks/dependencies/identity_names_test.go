package dependencies

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

// namedRoleRule is roleRule as the rebuilt packs write it: the identity is
// still "unknown", and the name and prefix attributes are beside it.
func namedRoleRule() ExistenceRule {
	rule := roleRule()
	rule.TargetIdentity = IdentityUnknown
	rule.TargetIdentityName, rule.TargetIdentityPrefix = "name", "name_prefix"
	return rule
}

// rolePlan has a function that names a role by literal ARN, and one planned
// role with the given attributes.
func rolePlan(literal string, role map[string]any, unknown map[string]any) Plan {
	if unknown == nil {
		unknown = map[string]any{}
	}
	return Plan{
		References: map[string]map[string]AttributeReference{"aws_lambda_function.f": {"role": {Attribute: "role", Origin: OriginLiteral}}},
		Actions:    map[string][]string{},
		Changes: map[string]PlannedValues{
			"aws_lambda_function.f": {
				Address: "aws_lambda_function.f", ResourceType: "aws_lambda_function", Actions: []string{"create"},
				After: map[string]any{"role": literal}, AfterUnknown: map[string]any{},
			},
			"aws_iam_role.r": {
				Address: "aws_iam_role.r", ResourceType: "aws_iam_role", Actions: []string{"create"},
				After: role, AfterUnknown: unknown,
			},
		},
		Providers: map[string]string{"aws_lambda_function.f": DefaultProvider},
	}
}

func evaluateRole(rule ExistenceRule, plan Plan, scope Scope) Result {
	resolver := &fakeResolver{answers: map[string]Existence{}}
	for _, name := range []string{"app", "app-prod", "other"} {
		resolver.answers[name] = NotFound
	}
	results, _ := Engine{Existence: []ExistenceRule{rule}, Resolver: resolver, Scope: scope}.Evaluate(context.Background(), plan)
	for _, result := range results {
		if result.Address == "aws_lambda_function.f" {
			return result
		}
	}
	return Result{}
}

var accountScope = Scope{Region: "us-east-1", Account: "123456789012", Partition: "aws"}

const appARN = "arn:aws:iam::123456789012:role/app"

// Every way the new identity can answer, for a role named by ARN.
func TestNamedIdentityDecidesASamePlanRole(t *testing.T) {
	for _, tc := range []struct {
		name    string
		literal string
		role    map[string]any
		unknown map[string]any
		scope   Scope
		want    string
		finding bool
	}{
		{name: "same name is created by this plan", literal: appARN, role: map[string]any{"name": "app"}, scope: accountScope, want: VerdictOrderingRisk, finding: true},
		{name: "another name is plainly missing", literal: "arn:aws:iam::123456789012:role/other", role: map[string]any{"name": "app"}, scope: accountScope, want: VerdictViolation, finding: true},
		{name: "same name, another account", literal: "arn:aws:iam::210987654321:role/app", role: map[string]any{"name": "app"}, scope: accountScope, want: VerdictPartial},
		{name: "same name, account unknown", literal: appARN, role: map[string]any{"name": "app"}, scope: Scope{Region: "us-east-1", Partition: "aws"}, want: VerdictPartial},
		{name: "same name, partition unknown", literal: appARN, role: map[string]any{"name": "app"}, scope: Scope{Region: "us-east-1", Account: "123456789012"}, want: VerdictPartial},
		{name: "same name, another partition", literal: "arn:aws-cn:iam::123456789012:role/app", role: map[string]any{"name": "app"}, scope: accountScope, want: VerdictPartial},
		{name: "same name in another letter case", literal: "arn:aws:iam::123456789012:role/App", role: map[string]any{"name": "app"}, scope: accountScope, want: VerdictPartial},
		{name: "role behind a path", literal: "arn:aws:iam::123456789012:role/service-role/app", role: map[string]any{"name": "app"}, scope: accountScope, want: VerdictOrderingRisk, finding: true},
		{name: "prefix the literal starts with", literal: "arn:aws:iam::123456789012:role/app-prod", role: map[string]any{"name_prefix": "app-"}, scope: accountScope, want: VerdictPartial},
		{name: "prefix the literal does not start with", literal: "arn:aws:iam::123456789012:role/other", role: map[string]any{"name_prefix": "app-"}, scope: accountScope, want: VerdictViolation, finding: true},
		{name: "prefix in another letter case", literal: "arn:aws:iam::123456789012:role/APP-prod", role: map[string]any{"name_prefix": "app-"}, scope: accountScope, want: VerdictPartial},
		{name: "a name wins over a prefix", literal: "arn:aws:iam::123456789012:role/app-prod", role: map[string]any{"name": "app", "name_prefix": "app-"}, scope: accountScope, want: VerdictViolation, finding: true},
		{name: "neither set", literal: appARN, role: map[string]any{}, unknown: map[string]any{"name": true, "name_prefix": true}, scope: accountScope, want: VerdictPartial},
		{name: "name not known until apply", literal: appARN, role: map[string]any{}, unknown: map[string]any{"name": true}, scope: accountScope, want: VerdictPartial},
		{name: "empty name", literal: appARN, role: map[string]any{"name": ""}, scope: accountScope, want: VerdictPartial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := evaluateRole(namedRoleRule(), rolePlan(tc.literal, tc.role, tc.unknown), tc.scope)
			if result.Verdict != tc.want {
				t.Fatalf("verdict = %q (%s), want %q", result.Verdict, result.Reason, tc.want)
			}
			if (result.Finding != nil) != tc.finding {
				t.Fatalf("finding = %+v, want a finding: %v", result.Finding, tc.finding)
			}
			if result.Finding != nil && result.Finding.Severity != model.SeverityWarning {
				t.Fatalf("severity = %q, want a warning: nothing here may block", result.Finding.Severity)
			}
		})
	}
}

// Without the new fields the rule reads as before.
func TestUnknownIdentityWithoutNamesStaysPartial(t *testing.T) {
	rule := roleRule()
	rule.TargetIdentity = IdentityUnknown
	result := evaluateRole(rule, rolePlan(appARN, map[string]any{"name": "app"}, nil), accountScope)
	if result.Verdict != VerdictPartial {
		t.Fatalf("verdict = %q, want partial", result.Verdict)
	}
}

// A role in the plan does not matter when the identity says AWS picks the id.
func TestServerGeneratedStillSkipsTheSamePlanCheck(t *testing.T) {
	rule := namedRoleRule()
	rule.TargetIdentity = IdentityServerGenerated
	result := evaluateRole(rule, rolePlan(appARN, map[string]any{"name": "app"}, nil), accountScope)
	if result.Verdict != VerdictViolation {
		t.Fatalf("verdict = %q, want a plain missing target", result.Verdict)
	}
}

// A rule whose identity is a planned attribute and whose reference is an ARN
// now compares the name inside the ARN, not the whole ARN.
func TestAttributeIdentityReadsTheNameInsideAnARN(t *testing.T) {
	rule := roleRule() // TargetIdentity "name"
	if got := evaluateRole(rule, rolePlan(appARN, map[string]any{"name": "app"}, nil), accountScope); got.Verdict != VerdictOrderingRisk {
		t.Fatalf("verdict = %q, want an ordering risk", got.Verdict)
	}
	if got := evaluateRole(rule, rolePlan("arn:aws:iam::210987654321:role/app", map[string]any{"name": "app"}, nil), accountScope); got.Verdict != VerdictPartial {
		t.Fatalf("other account: verdict = %q, want partial", got.Verdict)
	}
	if got := evaluateRole(rule, rolePlan("arn:aws:iam::123456789012:role/other", map[string]any{"name": "app"}, nil), accountScope); got.Verdict != VerdictViolation {
		t.Fatalf("other name: verdict = %q, want a plain missing target", got.Verdict)
	}
}

// A name that differs only in letter case may be the same target (IAM user and
// role names are not case sensitive), so the answer is "couldn't check", never
// "does not exist". This is the planned-attribute path, not the name helpers.
func TestAttributeIdentityCaseOnlyDifferenceCouldNotBeChecked(t *testing.T) {
	rule := roleRule()
	if got := evaluateRole(rule, rolePlan(appARN, map[string]any{"name": "App"}, nil), accountScope); got.Verdict != VerdictPartial {
		t.Fatalf("ARN, case only: verdict = %q, want partial", got.Verdict)
	}
	if got := evaluateRole(rule, rolePlan(appARN, map[string]any{"name": "APP"}, nil), accountScope); got.Verdict != VerdictPartial {
		t.Fatalf("ARN, upper case: verdict = %q, want partial", got.Verdict)
	}
}

// An ARN whose published format has no account (S3) is checked on its name and
// partition alone; one with a region needs the region to match as well.
func TestARNFormatDecidesWhichPartsMustMatch(t *testing.T) {
	bucket := ExistenceRule{
		Resource: "aws_s3_bucket_policy", Operation: "create", Attribute: "bucket", Path: []string{"bucket"},
		TargetResource: "aws_s3_bucket", TargetAttribute: "arn", TargetIdentity: IdentityUnknown,
		TargetIdentityName: "bucket", TargetIdentityPrefix: "bucket_prefix",
		Key:    ReferenceKey{Kind: KeyARN, Normalization: NormalizationARNComponent, ARNService: "s3", ARNPrefix: "", ARNFormat: "arn:${Partition}:s3:::${BucketName}"},
		Lookup: Lookup{Service: "s3", Operation: "HeadBucket", Field: "Bucket", NotFoundType: "NotFound", NotFoundCodes: []string{"NoSuchBucket"}},
	}
	plan := func(literal string) Plan {
		return Plan{
			References: map[string]map[string]AttributeReference{"aws_s3_bucket_policy.p": {"bucket": {Attribute: "bucket", Origin: OriginLiteral}}},
			Actions:    map[string][]string{},
			Changes: map[string]PlannedValues{
				"aws_s3_bucket_policy.p": {Address: "aws_s3_bucket_policy.p", ResourceType: "aws_s3_bucket_policy", Actions: []string{"create"}, After: map[string]any{"bucket": literal}, AfterUnknown: map[string]any{}},
				"aws_s3_bucket.b":        {Address: "aws_s3_bucket.b", ResourceType: "aws_s3_bucket", Actions: []string{"create"}, After: map[string]any{"bucket": "logs"}, AfterUnknown: map[string]any{}},
			},
			Providers: map[string]string{"aws_s3_bucket_policy.p": DefaultProvider},
		}
	}
	run := func(rule ExistenceRule, literal string, scope Scope) Result {
		resolver := &fakeResolver{answers: map[string]Existence{"logs": NotFound, "arn:aws:s3:::logs": NotFound}}
		results, _ := Engine{Existence: []ExistenceRule{rule}, Resolver: resolver, Scope: scope}.Evaluate(context.Background(), plan(literal))
		for _, result := range results {
			if result.Address == "aws_s3_bucket_policy.p" {
				return result
			}
		}
		return Result{}
	}
	if got := run(bucket, "arn:aws:s3:::logs", accountScope); got.Verdict != VerdictOrderingRisk {
		t.Fatalf("bucket without an account in its ARN: verdict = %q (%s), want an ordering risk", got.Verdict, got.Reason)
	}
	if got := run(bucket, "arn:aws:s3:::logs", Scope{Partition: "aws-cn"}); got.Verdict != VerdictPartial {
		t.Fatalf("another partition: verdict = %q, want partial", got.Verdict)
	}
	regional := bucket
	regional.Key.ARNFormat = "arn:${Partition}:s3:${Region}:${Account}:${BucketName}"
	if got := run(regional, "arn:aws:s3:us-west-2:123456789012:logs", accountScope); got.Verdict != VerdictPartial {
		t.Fatalf("another region: verdict = %q, want partial", got.Verdict)
	}
}

// A pack written before the new fields, and one written with them, both load.
func TestRuleJSONCarriesTheNewFieldsOnlyWhenSet(t *testing.T) {
	var old ExistenceRule
	if err := json.Unmarshal([]byte(`{"resource":"a","target_resource":"b","target_identity":"unknown"}`), &old); err != nil {
		t.Fatal(err)
	}
	if old.TargetIdentityName != "" || old.TargetIdentityPrefix != "" {
		t.Fatalf("old rule = %+v", old)
	}
	data, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	var written map[string]json.RawMessage
	if err := json.Unmarshal(data, &written); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"target_identity_name", "target_identity_prefix"} {
		if _, present := written[field]; present {
			t.Fatalf("an unset %s must not be written: %s", field, data)
		}
	}
	var fresh ExistenceRule
	if err := json.Unmarshal([]byte(`{"target_identity":"unknown","target_identity_name":"name","target_identity_prefix":"name_prefix"}`), &fresh); err != nil {
		t.Fatal(err)
	}
	if fresh.TargetIdentity != IdentityUnknown || fresh.TargetIdentityName != "name" || fresh.TargetIdentityPrefix != "name_prefix" {
		t.Fatalf("fresh rule = %+v", fresh)
	}
}
