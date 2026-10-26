package conflicts

import (
	"context"
	"fmt"
	"strings"

	"github.com/tfpreflight/tfpreflight/internal/packs"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// iamNameLookupAPI is the built-in IAM name check. It covers roles only: the
// generated resolver checks users and groups, and checking them here too
// reported every collision twice.
type iamNameLookupAPI interface {
	GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error)
}
type iamNameRequirement struct {
	change     model.PlannedChange
	name, kind string
}

// PredictIAMNameConflicts reports planned IAM roles whose name AWS already has.
// A lookup that fails other than with not-found gives an informational finding,
// never a conflict.
func PredictIAMNameConflicts(ctx context.Context, config awssdk.Config, rules []packs.ResolvedRule) ([]model.Finding, error) {
	requirements := iamNameRequirements(rules)
	if len(requirements) == 0 {
		return nil, nil
	}
	return checkIAMNameConflicts(ctx, requirements, iam.NewFromConfig(config))
}

func iamNameRequirements(rules []packs.ResolvedRule) []iamNameRequirement {
	var out []iamNameRequirement
	for _, rule := range rules {
		if rule.Action.Conflict == nil || rule.Action.Conflict.Type != "iam_name_exists" {
			continue
		}
		name, ok := packs.ValueForField(rule.Change, rule.Action.Conflict.IdentityField)
		if !ok {
			continue
		}
		kind := rule.Change.ResourceType
		out = append(out, iamNameRequirement{rule.Change, name, kind})
	}
	return out
}

func checkIAMNameConflicts(ctx context.Context, requirements []iamNameRequirement, client iamNameLookupAPI) ([]model.Finding, error) {
	var findings []model.Finding
	for _, r := range requirements {
		exists := false
		var err error
		switch r.kind {
		case "aws_iam_role":
			_, err = client.GetRole(ctx, &iam.GetRoleInput{RoleName: &r.name})
		default:
			continue
		}
		if err == nil {
			exists = true
		} else if statusCode(err) != 404 {
			findings = append(findings, iamNameLookupUnavailable(r, err))
			continue
		}
		if exists {
			findings = append(findings, iamNameConflict(r))
		}
	}
	return findings, nil
}

func iamNameConflict(r iamNameRequirement) model.Finding {
	return model.Finding{
		ID: "aws.iam-name-conflict", Provider: "aws", Resource: r.change.Address, Category: "resource-conflict", Severity: model.SeverityError, Confidence: model.ConfidenceHigh, Title: "Apply will likely fail", Operation: "Create IAM " + r.kind[8:] + "\n" + r.name, Problem: "An IAM " + r.kind[8:] + " with this name already exists.", Explanation: "Terraform plans to create an account-scoped IAM name that AWS already has.", Remediation: "Use a different name or import the existing resource if Terraform should manage it.",
		Brief: fmt.Sprintf("IAM %s name %q is already taken.", r.kind[8:], r.name), Next: "Fix: use a different name, or import the existing " + r.kind[8:] + ".",
	}
}

func iamNameLookupUnavailable(r iamNameRequirement, err error) model.Finding {
	return model.Finding{
		ID: "aws.iam-name-conflict-unavailable", Provider: "aws", Resource: r.change.Address, Category: "resource-conflict", Severity: model.SeverityInfo, Confidence: model.ConfidenceLow, Title: "IAM name availability could not be verified", Explanation: "Could not verify whether this IAM name already exists with the current AWS identity.", Notes: []string{verificationErrorNote(err)}, AWSError: verificationErrorNote(err),
		Brief: fmt.Sprintf("Could not check whether IAM %s name %q is taken.", r.kind[8:], r.name), Next: "Check: " + strings.Replace(verificationErrorNote(err), "the bucket", "the name", 1),
	}
}
