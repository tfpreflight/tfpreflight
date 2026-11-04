package adapters

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/checks/dependencies"
)

// A bucket in another account answers a HEAD with 403, and one in another
// region with 301. Neither says the bucket does not exist. Only a real
// not-found makes a finding; every other answer leaves the check partial, so a
// valid cross-account or cross-region bucket is never reported missing.
func TestOnlyARealNotFoundMakesAnS3BucketMissing(t *testing.T) {
	otherRegion := http.Header{"X-Amz-Bucket-Region": {"eu-west-1"}}
	for _, tc := range []struct {
		name    string
		status  int
		header  http.Header
		body    string
		want    dependencies.Existence
		verdict string
	}{
		{"the bucket exists", 200, nil, ``, dependencies.Exists, dependencies.VerdictSatisfied},
		{"404 with no body", 404, nil, ``, dependencies.NotFound, dependencies.VerdictViolation},
		{"404 NoSuchBucket", 404, nil, `<Error><Code>NoSuchBucket</Code></Error>`, dependencies.NotFound, dependencies.VerdictViolation},
		{"403 with no body: another account's bucket", 403, nil, ``, dependencies.Unknown, dependencies.VerdictPartial},
		{"403 AccessDenied", 403, nil, `<Error><Code>AccessDenied</Code></Error>`, dependencies.Unknown, dependencies.VerdictPartial},
		{"301 from another region", 301, otherRegion, ``, dependencies.Unknown, dependencies.VerdictPartial},
		{"301 PermanentRedirect", 301, otherRegion, `<Error><Code>PermanentRedirect</Code></Error>`, dependencies.Unknown, dependencies.VerdictPartial},
		{"400", 400, nil, ``, dependencies.Unknown, dependencies.VerdictPartial},
		{"500", 500, nil, ``, dependencies.Unknown, dependencies.VerdictPartial},
		{"503 SlowDown", 503, nil, `<Error><Code>SlowDown</Code></Error>`, dependencies.Unknown, dependencies.VerdictPartial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			answer := func(*http.Request) (*http.Response, error) {
				header := http.Header{}
				for key, values := range tc.header {
					header[key] = values
				}
				return &http.Response{StatusCode: tc.status, Header: header, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			}
			lookup := compiledLookup(t, "s3/HeadBucket/Bucket")
			got, reason := New("6.64.0", testConfig(answer)).Exists(context.Background(), lookup, dependencies.Scope{}, "example-bucket")
			if got != tc.want {
				t.Fatalf("lookup = %s (%s), want %s", got, reason, tc.want)
			}

			// The same answer through the engine, as a plan that names the bucket.
			rule := dependencies.ExistenceRule{
				Resource: "aws_cloudtrail", Operation: "create", Attribute: "s3_bucket_name",
				TargetResource: "aws_s3_bucket", TargetAttribute: "id", TargetIdentity: dependencies.IdentityUnknown,
				Lookup: lookup,
			}
			plan := dependencies.Plan{
				References: map[string]map[string]dependencies.AttributeReference{
					"aws_cloudtrail.t": {"s3_bucket_name": {Attribute: "s3_bucket_name", Origin: dependencies.OriginLiteral}},
				},
				Changes: map[string]dependencies.PlannedValues{
					"aws_cloudtrail.t": {
						Address: "aws_cloudtrail.t", ResourceType: "aws_cloudtrail", Actions: []string{"create"},
						After: map[string]any{"s3_bucket_name": "example-bucket"}, AfterUnknown: map[string]any{},
					},
				},
				Providers: map[string]string{"aws_cloudtrail.t": dependencies.DefaultProvider},
			}
			engine := dependencies.Engine{Existence: []dependencies.ExistenceRule{rule}, Resolver: New("6.64.0", testConfig(answer))}
			results, _ := engine.Evaluate(context.Background(), plan)
			if len(results) != 1 {
				t.Fatalf("results = %+v, want one", results)
			}
			result := results[0]
			if result.Verdict != tc.verdict {
				t.Fatalf("verdict = %s (%s), want %s", result.Verdict, result.Reason, tc.verdict)
			}
			if (result.Finding != nil) != (tc.verdict == dependencies.VerdictViolation) {
				t.Fatalf("finding = %+v for verdict %s", result.Finding, result.Verdict)
			}
		})
	}
}
