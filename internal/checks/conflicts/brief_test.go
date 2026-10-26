package conflicts

import (
	"errors"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

func TestEveryFindingHasABrief(t *testing.T) {
	bucket := bucketRequirement{change: model.PlannedChange{Address: "aws_s3_bucket.logs"}, bucket: "acme-logs"}
	taken := bucketConflictFinding(bucket)
	if taken.Brief != `Bucket name "acme-logs" is already taken.` || taken.Next != "Fix: use a different name, or import the existing bucket." {
		t.Errorf("brief = %q, next = %q", taken.Brief, taken.Next)
	}
	role := iamNameRequirement{change: model.PlannedChange{Address: "aws_iam_role.app"}, name: "app", kind: "aws_iam_role"}
	if got := iamNameConflict(role).Brief; got != `IAM role name "app" is already taken.` {
		t.Errorf("brief = %q", got)
	}
	if got := iamNameLookupUnavailable(role, errors.New("boom")).Next; got != "Check: AWS returned an unexpected response while checking the name." {
		t.Errorf("next = %q", got)
	}
	change := model.PlannedChange{Address: "aws_sqs_queue.q", ResourceType: "aws_sqs_queue"}
	composite := Rule{IdentityField: "name", Identity: Identity{Parts: []IdentityPart{{}, {}}}}
	for _, finding := range []model.Finding{
		taken,
		bucketVerificationUnavailableFinding(bucket, errors.New("boom")),
		iamNameConflict(role),
		iamNameLookupUnavailable(role, errors.New("boom")),
		conflictFinding(change, Rule{IdentityField: "name"}, []string{"name = jobs"}),
		conflictFinding(change, composite, []string{"name = jobs", "role = arn:aws:iam::123456789012:role/app"}),
		lookupUnavailable(change, Rule{}, "SQS queue jobs", errors.New("boom")),
	} {
		assertBrief(t, finding)
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
