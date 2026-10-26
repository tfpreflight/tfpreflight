package quotas

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/packs"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/servicequotas"
	servicequotastypes "github.com/aws/aws-sdk-go-v2/service/servicequotas/types"
	packdata "github.com/tfpreflight/tfpreflight/packs"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

type fakeEC2Client struct {
	vcpus int32
	err   error
}

func (f fakeEC2Client) DescribeInstanceTypes(_ context.Context, _ *ec2.DescribeInstanceTypesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstanceTypesOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &ec2.DescribeInstanceTypesOutput{InstanceTypes: []types.InstanceTypeInfo{{VCpuInfo: &types.VCpuInfo{DefaultVCpus: &f.vcpus}}}}, nil
}

type fakeQuotaClient struct {
	value float64
	err   error
}

func (f fakeQuotaClient) GetServiceQuota(_ context.Context, _ *servicequotas.GetServiceQuotaInput, _ ...func(*servicequotas.Options)) (*servicequotas.GetServiceQuotaOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &servicequotas.GetServiceQuotaOutput{Quota: &servicequotastypes.ServiceQuota{Value: aws.Float64(f.value)}}, nil
}

func TestCheckEC2VCPUQuota(t *testing.T) {
	requirement := EC2QuotaRequirement{Change: model.PlannedChange{Address: "aws_instance.quota_test"}, InstanceType: "m6i.8xlarge", Region: "us-east-1"}
	tests := []struct {
		name           string
		ec2            fakeEC2Client
		quota          fakeQuotaClient
		wantFindings   int
		wantSeverity   model.Severity
		wantConfidence model.Confidence
	}{
		{name: "32 vcpus exceeds quota 16", ec2: fakeEC2Client{vcpus: 32}, quota: fakeQuotaClient{value: 16}, wantFindings: 1, wantSeverity: model.SeverityError, wantConfidence: model.ConfidenceHigh},
		{name: "8 vcpus within quota 16", ec2: fakeEC2Client{vcpus: 8}, quota: fakeQuotaClient{value: 16}, wantFindings: 0},
		{name: "quota error", ec2: fakeEC2Client{vcpus: 32}, quota: fakeQuotaClient{err: errors.New("denied")}, wantFindings: 1, wantSeverity: model.SeverityInfo, wantConfidence: model.ConfidenceLow},
		{name: "instance type error", ec2: fakeEC2Client{err: errors.New("not found")}, quota: fakeQuotaClient{value: 16}, wantFindings: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := checkEC2VCPUQuota(context.Background(), requirement, test.ec2, test.quota)
			if len(findings) != test.wantFindings {
				t.Fatalf("len(findings) = %d, want %d", len(findings), test.wantFindings)
			}
			if len(findings) > 0 && (findings[0].Severity != test.wantSeverity || findings[0].Confidence != test.wantConfidence) {
				t.Fatalf("unexpected finding: %#v", findings[0])
			}
			if test.wantSeverity == model.SeverityError && findings[0].ID != "aws.ec2-standard-on-demand-vcpu-quota" {
				t.Fatalf("blocking finding ID = %q", findings[0].ID)
			}
		})
	}
}

func TestVerifiedEC2VCPUQuotaCheckIsRegisteredSeparatelyFromGeneratedRules(t *testing.T) {
	checks := VerifiedQuotaChecks()
	if len(checks) != 1 || checks[0].Resource != "aws_instance" || checks[0].QuotaCode != standardOnDemandVCPUQuotaCode || checks[0].Trust != "verified" {
		t.Fatalf("verified quota checks = %#v", checks)
	}
}

func TestEC2QuotaRequirementsSkipUnsupportedChanges(t *testing.T) {
	changes := []model.PlannedChange{
		{ResourceType: "aws_instance", ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate, After: map[string]any{"instance_type": "t3.micro", "region": "us-east-1"}},
		{ResourceType: "aws_s3_bucket", ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate, After: map[string]any{"instance_type": "m6i.8xlarge", "region": "us-east-1"}},
		{ResourceType: "aws_instance", ProviderName: "registry.terraform.io/hashicorp/aws", Action: model.ActionCreate, After: map[string]any{"instance_type": "m6i.8xlarge"}},
	}
	if got := EC2QuotaRequirements(resolvedForTest(t, changes)); len(got) != 0 {
		t.Fatalf("EC2QuotaRequirements() = %#v, want no requirements", got)
	}
}

// resolvedForTest resolves the shipped pack for a set of planned changes.
// resolvedForTest resolves against the hand-written default pack, the same
// pack these tests used before the runtime was split into packages.
func resolvedForTest(t *testing.T, changes []model.PlannedChange) []packs.ResolvedRule {
	t.Helper()
	data, err := packdata.AWS.ReadFile("aws/knowledge/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack packs.KnowledgePack
	if err := json.Unmarshal(data, &pack); err != nil {
		t.Fatal(err)
	}
	return packs.ResolveRules(pack, changes)
}
