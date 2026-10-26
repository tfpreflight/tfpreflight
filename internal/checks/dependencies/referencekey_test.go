package dependencies

import (
	"context"
	"strings"
	"testing"
)

// roleRule references an IAM role by ARN: AWS publishes the role ARN as
// role/${RoleNameWithPath}, and GetRole consumes the name.
func roleRule() ExistenceRule {
	return ExistenceRule{
		Resource: "aws_lambda_function", Operation: "create", Attribute: "role", Path: []string{"role"},
		TargetResource: "aws_iam_role", TargetAttribute: "arn", TargetIdentity: "name",
		Key: ReferenceKey{
			Kind: KeyARN, Normalization: NormalizationARNLastSegment,
			ARNService: "iam", ARNPrefix: "role/", ARNFormat: "arn:${Partition}:iam::${Account}:role/${RoleNameWithPath}",
		},
		Lookup: Lookup{Service: "iam", Operation: "GetRole", Field: "RoleName", NotFoundType: "NoSuchEntityException"},
	}
}

// The value a lookup receives is read out of the ARN exactly where AWS's
// published format says it sits.
func TestReferenceKeyReadsThePublishedComponent(t *testing.T) {
	for _, tc := range []struct {
		name, arn, want, refusal string
		key                      ReferenceKey
	}{
		{name: "role name", arn: "arn:aws:iam::123456789012:role/app", want: "app", key: roleRule().Key},
		{name: "role behind a path", arn: "arn:aws:iam::123456789012:role/service-role/app", want: "app", key: roleRule().Key},
		{name: "wrong service", arn: "arn:aws:ecs:us-east-1:123456789012:role/app", refusal: "belongs to ecs", key: roleRule().Key},
		{name: "not an ARN", arn: "app", refusal: "does not hold an ARN", key: roleRule().Key},
		{name: "too few sections", arn: "arn:aws:iam:role/app", refusal: "does not hold an ARN", key: roleRule().Key},
		{name: "another resource type", arn: "arn:aws:iam::123456789012:user/app", refusal: "does not match the published format", key: roleRule().Key},
		{
			name: "kms key", arn: "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef", want: "1234abcd-12ab-34cd-56ef",
			key: ReferenceKey{
				Kind: KeyARN, Normalization: NormalizationARNComponent, ARNService: "kms", ARNPrefix: "key/",
				ARNFormat: "arn:${Partition}:kms:${Region}:${Account}:key/${KeyId}",
			},
		},
		{
			name: "lambda function", arn: "arn:aws:lambda:us-east-1:123456789012:function:handler", want: "handler",
			key: ReferenceKey{
				Kind: KeyARN, Normalization: NormalizationARNComponent, ARNService: "lambda", ARNPrefix: "function:",
				ARNFormat: "arn:${Partition}:lambda:${Region}:${Account}:function:${FunctionName}",
			},
		},
		{
			name: "qualified lambda function", arn: "arn:aws:lambda:us-east-1:123456789012:function:handler:PROD",
			refusal: "carries more than the published format",
			key: ReferenceKey{
				Kind: KeyARN, Normalization: NormalizationARNComponent, ARNService: "lambda", ARNPrefix: "function:",
				ARNFormat: "arn:${Partition}:lambda:${Region}:${Account}:function:${FunctionName}",
			},
		},
		{name: "a name passes through", arn: "app", want: "app", key: ReferenceKey{Kind: KeyName, Normalization: NormalizationNone}},
		{
			name: "an ARN-keyed lookup takes the ARN", arn: "arn:aws:sns:us-east-1:123456789012:topic", want: "arn:aws:sns:us-east-1:123456789012:topic",
			key: ReferenceKey{Kind: KeyARN, Normalization: NormalizationNone},
		},
		{name: "a rule compiled before key semantics", arn: "vpc-1", want: "vpc-1", key: ReferenceKey{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, refusal := tc.key.LookupValue(tc.arn)
			if tc.refusal != "" {
				if refusal == "" || !strings.Contains(refusal, tc.refusal) {
					t.Fatalf("value = %q, refusal = %q, want a refusal containing %q", got, refusal, tc.refusal)
				}
				return
			}
			if refusal != "" || got != tc.want {
				t.Fatalf("value = %q (%s), want %q", got, refusal, tc.want)
			}
		})
	}
}

// A value that cannot be read as the lookup's key is unknown, never missing.
func TestUnreadableKeyIsPartialNotMissing(t *testing.T) {
	plan := subnetPlan(OriginLiteral, "arn:aws:ecs:us-east-1:123456789012:role/app", nil)
	change := plan.Changes["aws_subnet.s"]
	change.ResourceType = "aws_lambda_function"
	change.Address = "aws_lambda_function.f"
	change.After = map[string]any{"role": "arn:aws:ecs:us-east-1:123456789012:role/app"}
	plan.Changes = map[string]PlannedValues{"aws_lambda_function.f": change}
	plan.References = map[string]map[string]AttributeReference{
		"aws_lambda_function.f": {"role": {Attribute: "role", Origin: OriginLiteral}},
	}
	plan.Providers = map[string]string{"aws_lambda_function.f": DefaultProvider}
	resolver := &fakeResolver{answers: map[string]Existence{"app": NotFound}}
	results, _ := Engine{Existence: []ExistenceRule{roleRule()}, Resolver: resolver}.Evaluate(context.Background(), plan)
	result := resultFor(t, results, "aws_lambda_function.f")
	if result.Verdict != VerdictPartial || result.Finding != nil {
		t.Fatalf("result = %+v, want partial without a finding", result)
	}
	if resolver.calls != 0 {
		t.Fatalf("an unreadable key was sent to AWS %d times", resolver.calls)
	}
}

// A target this plan creates is never inspected, whether the configuration
// references it by id, by name or by ARN.
func TestSamePlanReferenceByAnyKeyIsNotInspected(t *testing.T) {
	for _, tc := range []struct {
		name  string
		key   ReferenceKey
		value any
	}{
		{"by ARN", roleRule().Key, "arn:aws:iam::123456789012:role/app"},
		{"by name", ReferenceKey{Kind: KeyName, Normalization: NormalizationNone}, "app"},
		{"unknown until apply", roleRule().Key, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := roleRule()
			rule.Key = tc.key
			unknown := any(nil)
			if tc.value == nil {
				unknown = true
			}
			plan := Plan{
				References: map[string]map[string]AttributeReference{
					"aws_lambda_function.f": {"role": {Attribute: "role", Origin: OriginSamePlan, Producers: []string{"aws_iam_role.app"}}},
				},
				Actions: map[string][]string{"aws_iam_role.app": {"create"}},
				Changes: map[string]PlannedValues{
					"aws_lambda_function.f": {
						Address: "aws_lambda_function.f", ResourceType: "aws_lambda_function", Actions: []string{"create"},
						After: map[string]any{"role": tc.value}, AfterUnknown: map[string]any{"role": unknown},
					},
					"aws_iam_role.app": {
						Address: "aws_iam_role.app", ResourceType: "aws_iam_role", Actions: []string{"create"},
						After: map[string]any{"name": "app", "arn": "arn:aws:iam::123456789012:role/app"}, AfterUnknown: map[string]any{},
					},
				},
				Providers: map[string]string{"aws_lambda_function.f": DefaultProvider},
			}
			resolver := &fakeResolver{answers: map[string]Existence{"app": NotFound}}
			results, _ := Engine{Existence: []ExistenceRule{rule}, Resolver: resolver}.Evaluate(context.Background(), plan)
			result := resultFor(t, results, "aws_lambda_function.f")
			if resolver.calls != 0 {
				t.Fatalf("%s: a target this plan creates was inspected %d times", tc.name, resolver.calls)
			}
			if result.Finding != nil {
				t.Fatalf("%s: result = %+v", tc.name, result)
			}
		})
	}
}

// An unreadable key is refused before AWS is asked, and a denied inspection of
// a readable one stays unknown.
func TestKeyResolutionKeepsTriState(t *testing.T) {
	plan := Plan{
		References: map[string]map[string]AttributeReference{
			"aws_lambda_function.f": {"role": {Attribute: "role", Origin: OriginLiteral}},
		},
		Actions: map[string][]string{},
		Changes: map[string]PlannedValues{"aws_lambda_function.f": {
			Address:      "aws_lambda_function.f",
			ResourceType: "aws_lambda_function", Actions: []string{"create"},
			After: map[string]any{"role": "arn:aws:iam::123456789012:role/app"}, AfterUnknown: map[string]any{},
		}},
		Providers: map[string]string{"aws_lambda_function.f": DefaultProvider},
	}
	// Unknown answer - an AccessDenied, a throttle - stays partial.
	resolver := &fakeResolver{answers: map[string]Existence{}}
	results, coverage := Engine{Existence: []ExistenceRule{roleRule()}, Resolver: resolver}.Evaluate(context.Background(), plan)
	if result := resultFor(t, results, "aws_lambda_function.f"); result.Verdict != VerdictPartial || result.Finding != nil {
		t.Fatalf("denied inspection = %+v", result)
	}
	if coverage["aws_lambda_function.f"] != CoveragePartial || resolver.calls != 1 {
		t.Fatalf("coverage = %s, calls = %d", coverage["aws_lambda_function.f"], resolver.calls)
	}
	// A proven miss on the normalised name is a finding.
	missing := &fakeResolver{answers: map[string]Existence{"app": NotFound}}
	results, _ = Engine{Existence: []ExistenceRule{roleRule()}, Resolver: missing}.Evaluate(context.Background(), plan)
	if result := resultFor(t, results, "aws_lambda_function.f"); result.Verdict != VerdictViolation || result.Finding == nil {
		t.Fatalf("missing role = %+v", result)
	}
}

// A format with no resource prefix, such as a bucket ARN, still has to reject
// anything the format does not describe: an object key, an access point, an
// ARN from another service. Nothing here may become MISSING.
func TestNoPrefixGrammarStillGuardsTheShape(t *testing.T) {
	key := ReferenceKey{
		Kind: KeyARN, Normalization: NormalizationARNComponent,
		ARNService: "s3", ARNPrefix: "",
		ARNFormat: "arn:${Partition}:s3:::${BucketName}",
	}
	if value, refusal := key.LookupValue("arn:aws:s3:::tfpreflight-bucket"); value != "tfpreflight-bucket" || refusal != "" {
		t.Fatalf("a bucket ARN = %q %q", value, refusal)
	}
	// Partitions are structural, never hard-coded.
	if value, refusal := key.LookupValue("arn:aws-us-gov:s3:::tfpreflight-bucket"); value != "tfpreflight-bucket" || refusal != "" {
		t.Fatalf("a GovCloud bucket ARN = %q %q", value, refusal)
	}
	for _, test := range []struct{ name, reference string }{
		{"an object inside the bucket", "arn:aws:s3:::tfpreflight-bucket/some/key"},
		{"an access point, not a bucket", "arn:aws:s3:us-east-1:123456789012:accesspoint/ap"},
		{"another service entirely", "arn:aws:sqs:us-east-1:123456789012:tfpreflight-queue"},
		{"not an ARN at all", "tfpreflight-bucket"},
	} {
		value, refusal := key.LookupValue(test.reference)
		if refusal == "" {
			t.Errorf("%s was read as %q instead of being refused", test.name, value)
		}
	}
}
