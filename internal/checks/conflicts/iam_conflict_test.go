package conflicts

import (
	"context"
	"errors"
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/packs"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

type fakeIAMLookup struct{ role error }

func (f fakeIAMLookup) GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	return &iam.GetRoleOutput{}, f.role
}

const testProviderVersion = "6.64.0"

func TestIAMNameConflictIsHighConfidenceOnlyWhenLookupFindsName(t *testing.T) {
	r := iamNameRequirement{change: model.PlannedChange{Address: "aws_iam_role.test"}, name: "taken", kind: "aws_iam_role"}
	findings, err := checkIAMNameConflicts(context.Background(), []iamNameRequirement{r}, fakeIAMLookup{})
	if err != nil || len(findings) != 1 || findings[0].Severity != model.SeverityError || findings[0].Confidence != model.ConfidenceHigh {
		t.Fatalf("%v %#v", err, findings)
	}
	findings, err = checkIAMNameConflicts(context.Background(), []iamNameRequirement{r}, fakeIAMLookup{role: errors.New("access denied")})
	if err != nil || len(findings) != 1 || findings[0].Severity != model.SeverityInfo {
		t.Fatalf("%v %#v", err, findings)
	}
}

func TestBuiltinConflictRulesAreExactResourceDefinitions(t *testing.T) {
	pack, _, err := packs.LoadRuntimePack(testProviderVersion)
	if err != nil {
		t.Fatal(err)
	}
	if pack.Resources["aws_iam_role"].Actions["create"].Conflict.Type != "iam_name_exists" {
		t.Fatal("role lookup rule missing")
	}
	if pack.Resources["aws_vpc"].Actions["create"].Conflict != nil {
		t.Fatal("unrelated resource acquired conflict lookup")
	}
}
