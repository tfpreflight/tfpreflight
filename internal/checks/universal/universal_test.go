package universal

import (
	"testing"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

func TestRunFindsUniversalIssues(t *testing.T) {
	changes := []model.PlannedChange{
		{Address: "aws_s3_bucket.old", ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionDelete},
		{Address: "aws_db_instance.main", ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionReplace},
		{Address: "aws_instance.web", ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate, AfterUnknown: map[string]any{"id": true}},
	}

	findings := Run(changes)
	if len(findings) != 3 {
		t.Fatalf("len(findings) = %d, want 3", len(findings))
	}
	if findings[0].Category != "destruction" || findings[1].Category != "replacement" || findings[2].Category != "unknown-values" {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}
