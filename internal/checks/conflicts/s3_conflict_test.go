package conflicts

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/packs"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	packdata "github.com/tfpreflight/tfpreflight/packs"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

type fakeS3Client struct {
	err    error
	bucket string
}

func (f *fakeS3Client) HeadBucket(_ context.Context, input *s3.HeadBucketInput, _ ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	f.bucket = *input.Bucket
	if f.err != nil {
		return nil, f.err
	}
	return &s3.HeadBucketOutput{}, nil
}

type headBucketError struct{ status int }

func (e headBucketError) Error() string       { return "head bucket failed" }
func (e headBucketError) HTTPStatusCode() int { return e.status }

func TestBucketRequirementsSkipsUnknownBucket(t *testing.T) {
	changes := []model.PlannedChange{{
		ResourceType: "aws_s3_bucket",
		ProviderName: "registry.terraform.io/hashicorp/aws",
		Action:       model.ActionCreate,
		After:        map[string]any{"bucket": "known-name"},
		AfterUnknown: map[string]any{"bucket": true},
	}}
	if got := bucketRequirements(resolvedForTest(t, changes)); len(got) != 0 {
		t.Fatalf("bucketRequirements() = %#v, want no requirements", got)
	}
}

func TestCheckBucketConflicts(t *testing.T) {
	requirements := []bucketRequirement{{
		change: model.PlannedChange{Address: "aws_s3_bucket.test"},
		bucket: "tfpreflight-conflict-test-123456789012-v2",
	}}

	tests := []struct {
		name           string
		err            error
		wantFindings   int
		wantSeverity   model.Severity
		wantConfidence model.Confidence
	}{
		{name: "exists", wantFindings: 1, wantSeverity: model.SeverityError, wantConfidence: model.ConfidenceHigh},
		{name: "not found", err: headBucketError{status: 404}, wantFindings: 0},
		{name: "access denied", err: headBucketError{status: 403}, wantFindings: 1, wantSeverity: model.SeverityInfo, wantConfidence: model.ConfidenceLow},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeS3Client{err: test.err}
			findings, err := checkBucketConflicts(context.Background(), requirements, client)
			if err != nil {
				t.Fatalf("checkBucketConflicts: %v", err)
			}
			if len(findings) != test.wantFindings {
				t.Fatalf("len(findings) = %d, want %d", len(findings), test.wantFindings)
			}
			if len(findings) > 0 && (findings[0].Severity != test.wantSeverity || findings[0].Confidence != test.wantConfidence) {
				t.Fatalf("unexpected finding: %#v", findings[0])
			}
		})
	}
}

func TestStatusCodeReturnsZeroForUnknownError(t *testing.T) {
	if got := statusCode(errors.New("unknown")); got != 0 {
		t.Fatalf("statusCode() = %d, want 0", got)
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
