package adapters

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/checks/dependencies"
)

// A zone id is often written with the /hostedzone/ prefix that some Route 53
// answers carry. The lookup must ask for the plain id: the AWS SDK strips the
// prefix, so a prefixed value reaches the same zone and a missing zone is
// reported missing, not "couldn't check".
func TestAHostedZoneIDWithThePrefixIsLookedUpAsThePlainID(t *testing.T) {
	const found = `<GetHostedZoneResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><HostedZone>` +
		`<Id>/hostedzone/Z0123456789ABC</Id><Name>example.com.</Name><CallerReference>ref</CallerReference></HostedZone></GetHostedZoneResponse>`
	const missing = `<ErrorResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><Error><Type>Sender</Type>` +
		`<Code>NoSuchHostedZone</Code><Message>No hosted zone found with ID: Z0123456789ABC</Message></Error><RequestId>r</RequestId></ErrorResponse>`
	for _, tc := range []struct {
		name   string
		id     string
		status int
		body   string
		want   dependencies.Existence
	}{
		{"plain id, zone exists", "Z0123456789ABC", 200, found, dependencies.Exists},
		{"prefixed id, zone exists", "/hostedzone/Z0123456789ABC", 200, found, dependencies.Exists},
		{"prefixed id without the leading slash, zone exists", "hostedzone/Z0123456789ABC", 200, found, dependencies.Exists},
		{"plain id, zone missing", "Z0123456789ABC", 404, missing, dependencies.NotFound},
		{"prefixed id, zone missing", "/hostedzone/Z0123456789ABC", 404, missing, dependencies.NotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var path string
			answer := func(request *http.Request) (*http.Response, error) {
				path = request.URL.Path
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": {"text/xml"}}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			}
			lookup := compiledLookup(t, "route53/GetHostedZone/Id")
			got, reason := New("6.64.0", testConfig(answer)).Exists(context.Background(), lookup, dependencies.Scope{}, tc.id)
			if got != tc.want {
				t.Fatalf("lookup = %s (%s), want %s", got, reason, tc.want)
			}
			if path != "/2013-04-01/hostedzone/Z0123456789ABC" {
				t.Errorf("the request went to %q, want the plain zone id", path)
			}
		})
	}
}
