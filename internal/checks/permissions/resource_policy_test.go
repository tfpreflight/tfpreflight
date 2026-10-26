package permissions

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

const existingKeyARN = "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"

func verifiedPermission(address, resourceType, permission string, after map[string]any, attributes ...string) plannedPermission {
	service, name, _ := strings.Cut(permission, ":")
	return plannedPermission{
		change:        model.PlannedChange{Address: address, ResourceType: resourceType, Action: model.ActionCreate, After: after},
		resourceLabel: resourceType, operationLabel: "Create",
		operation:  packs.OperationRule{Service: service, Name: name, Permission: permission, Trust: "verified"},
		attributes: attributes,
	}
}

func denyAll(decision types.PolicyEvaluationDecisionType) *policyIAM {
	return &policyIAM{decide: func(*iam.SimulatePrincipalPolicyInput) (types.PolicyEvaluationDecisionType, []string) {
		return decision, nil
	}}
}

// IAM's simulation reads no resource-based policy. An implicit deny on a
// resource that has one, or may, is a warning that says so; an explicit deny,
// or an implicit one no resource policy could lift, still blocks.
func TestImplicitDenyBlocksOnlyWhenNoResourcePolicyCouldAllow(t *testing.T) {
	implicit, explicit := types.PolicyEvaluationDecisionTypeImplicitDeny, types.PolicyEvaluationDecisionTypeExplicitDeny
	// An existing customer managed key: its key policy can allow the deploy
	// role what no IAM policy does.
	keyGrant := verifiedPermission("aws_ebs_volume.data", "aws_ebs_volume", "kms:CreateGrant",
		map[string]any{"kms_key_id": existingKeyARN, "size": float64(10)}, "kms_key_id", "size")
	// A bucket that exists outside the plan: its bucket policy can allow the
	// deploy role to change it.
	bucketVersioning := verifiedPermission("aws_s3_bucket_versioning.logs", "aws_s3_bucket_versioning", "s3:PutBucketVersioning",
		map[string]any{"bucket": "existing-logs"}, "bucket")
	bucketPolicy := verifiedPermission("aws_s3_bucket_policy.logs", "aws_s3_bucket_policy", "s3:PutBucketPolicy",
		map[string]any{"bucket": "existing-logs"}, "bucket")
	// A bucket this plan creates has no policy before CreateBucket.
	newBucket := verifiedPermission("aws_s3_bucket.new", "aws_s3_bucket", "s3:CreateBucket",
		map[string]any{"bucket": "brand-new-logs"}, "bucket")
	// IAM roles take no resource-based policy that grants IAM actions.
	attachPolicy := verifiedPermission("aws_iam_role_policy_attachment.app", "aws_iam_role_policy_attachment", "iam:AttachRolePolicy",
		map[string]any{"role": "app"}, "role")

	for name, tc := range map[string]struct {
		requirement plannedPermission
		decision    types.PolicyEvaluationDecisionType
		blocks      bool
		simulated   string
	}{
		"KMS key policy may allow an implicit deny": {keyGrant, implicit, false, existingKeyARN},
		"KMS explicit deny still blocks":            {keyGrant, explicit, true, existingKeyARN},
		"existing bucket's policy may allow":        {bucketVersioning, implicit, false, "arn:aws:s3:::existing-logs"},
		"replacing an existing bucket policy":       {bucketPolicy, implicit, false, "arn:aws:s3:::existing-logs"},
		"existing bucket, explicit deny":            {bucketVersioning, explicit, true, "arn:aws:s3:::existing-logs"},
		"creating a brand-new bucket":               {newBucket, implicit, true, "arn:aws:s3:::brand-new-logs"},
		"service without resource policies":         {attachPolicy, implicit, true, "arn:aws:iam::123456789012:role/app"},
	} {
		t.Run(name, func(t *testing.T) {
			client := denyAll(tc.decision)
			result := simulatePermissions(context.Background(), client, principal, testScope, []plannedPermission{tc.requirement})
			if len(result.Findings) != 1 {
				t.Fatalf("findings = %+v, partial %v", result.Findings, result.Partial)
			}
			if got := client.inputs[0].ResourceArns[0]; got != tc.simulated {
				t.Fatalf("simulated against %s, want %s", got, tc.simulated)
			}
			finding := result.Findings[0]
			if blocks := finding.Severity == model.SeverityError; blocks != tc.blocks {
				t.Fatalf("blocks = %v, want %v: %+v", blocks, tc.blocks, finding)
			}
			if !tc.blocks && !strings.Contains(strings.Join(finding.Notes, " "), "resource-based policy on "+tc.simulated) {
				t.Fatalf("a warning must say a resource policy could allow it: %v", finding.Notes)
			}
		})
	}
}
