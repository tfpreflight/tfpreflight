package awscall

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/tfpreflight/tfpreflight/rules"
)

// The one failure format, for every protocol:
//
//	<service>:<operation> failed: <ErrorCode> (HTTP <status>), request ID <id>
//	<message>
//
// with the parts AWS did not send left out.
func TestFailureFormat(t *testing.T) {
	for _, c := range []struct {
		failure Failure
		want    string
	}{
		{
			Failure{Service: "glue", Operation: "GetJob", Code: "AccessDeniedException", Status: 400, RequestID: "req-1", Message: "User is not authorized"},
			"glue:GetJob failed: AccessDeniedException (HTTP 400), request ID req-1\nUser is not authorized",
		},
		{
			Failure{Service: "glue", Operation: "GetJob", Code: "AccessDeniedException", Status: 400},
			"glue:GetJob failed: AccessDeniedException (HTTP 400)",
		},
		{
			Failure{Service: "iam", Operation: "GetUser", Status: 503, RequestID: "req-2"},
			"iam:GetUser failed: HTTP 503, request ID req-2",
		},
		{
			Failure{Service: "iam", Operation: "GetUser", Status: 200, Cause: "response could not be read", RequestID: "req-3"},
			"iam:GetUser failed: response could not be read (HTTP 200), request ID req-3",
		},
		{
			Failure{Service: "rds", Operation: "DescribeDBProxies", Cause: "no response from AWS", Message: `Post "https://rds.us-east-1.amazonaws.com/": dial tcp: connection refused`},
			"rds:DescribeDBProxies failed: no response from AWS\nPost \"https://rds.us-east-1.amazonaws.com/\": dial tcp: connection refused",
		},
		{
			Failure{Service: "lambda", Operation: "GetAlias", Cause: "inspection timed out"},
			"lambda:GetAlias failed: inspection timed out",
		},
	} {
		if got := c.failure.Error(); got != c.want {
			t.Errorf("got\n%s\nwant\n%s", got, c.want)
		}
	}
}

// Each protocol's request ID and message reach the failure.
func TestFailureFromEachProtocol(t *testing.T) {
	specs := loadSpecs(t)
	responses := loadResponses(t)
	for operation, spec := range specs {
		denied := responses[operation]["access_denied"]
		response := denied
		if response.Headers == nil {
			response.Headers = map[string]string{}
		}
		if spec.Protocol != rules.AWSQuery && spec.Protocol != rules.EC2Query {
			response.Headers["X-Amzn-Requestid"] = "req-from-header"
		}
		var slept []time.Duration
		answer := testEngine(&fakeClient{responses: []recorded{response}}, &slept).Inspect(context.Background(), spec, "us-east-1", map[string]string{spec.Field: identifiers[operation]})
		if answer.Result != Unknown || answer.Failure == nil {
			t.Fatalf("%s: %+v", operation, answer)
		}
		text := answer.Failure.Error()
		head := spec.Service + ":" + spec.Operation + " failed: "
		if !strings.HasPrefix(text, head) || answer.Failure.Code == "" || answer.Failure.Status != denied.Status || answer.Failure.RequestID == "" || answer.Failure.Message == "" {
			t.Errorf("%s (%s): %q, %+v", operation, spec.Protocol, text, answer.Failure)
		}
	}
}

// A lookup sends every input member, each where its input says.
func TestMultipleInputs(t *testing.T) {
	values := map[string]string{"A": "one/1", "B": "two", "C": "three"}
	base := &url.URL{Scheme: "https", Host: "example.amazonaws.com"}
	for _, c := range []struct {
		spec       Spec
		url, body  string
		header     string
		headerWant string
	}{
		{
			Spec{Protocol: rules.RestJSON1, Method: "GET", Path: "/things/{A}/parts/{B}", Inputs: []rules.Input{
				{Member: "A", Location: rules.InLabel, Name: "A"}, {Member: "B", Location: rules.InLabel, Name: "B"}, {Member: "C", Location: rules.InQuery, Name: "c"},
			}},
			"https://example.amazonaws.com/things/one%2F1/parts/two?c=three", "", "", "",
		},
		{
			Spec{Protocol: rules.RestJSON1, Method: "POST", Path: "/things/{A}", Inputs: []rules.Input{
				{Member: "A", Location: rules.InLabel, Name: "A"}, {Member: "B", Location: rules.InBody, Name: "b"}, {Member: "C", Location: rules.InHeader, Name: "X-C"},
			}},
			"https://example.amazonaws.com/things/one%2F1", `{"b":"two"}`, "X-C", "three",
		},
		{
			Spec{Protocol: rules.AWSJSON11, Target: "S.Op", Inputs: []rules.Input{
				{Member: "A", Location: rules.InBody, Name: "a"}, {Member: "B", Location: rules.InBody, Name: "b", List: true},
			}},
			"https://example.amazonaws.com/", `{"a":"one/1","b":["two"]}`, "", "",
		},
		{
			Spec{Protocol: rules.AWSQuery, Operation: "Op", APIVersion: "2020-01-01", Inputs: []rules.Input{
				{Member: "A", Location: rules.InBody, Name: "A"}, {Member: "B", Location: rules.InBody, Name: "Bs", List: true, ListMember: "member"},
			}},
			"https://example.amazonaws.com/", "A=one%2F1&Action=Op&Bs.member.1=two&Version=2020-01-01", "", "",
		},
	} {
		request, err := buildRequest(context.Background(), c.spec, base, values)
		if err != nil {
			t.Fatal(err)
		}
		var body []byte
		if request.Body != nil {
			body, _ = io.ReadAll(request.Body)
		}
		if request.URL.String() != c.url || string(body) != c.body || c.header != "" && request.Header.Get(c.header) != c.headerWant {
			t.Errorf("%s: %s %q %v", c.spec.Protocol, request.URL, body, request.Header)
		}
	}
}

// A required member the lookup does not send stops it before anything is
// sent, as the SDK's validation does.
func TestMissingRequiredIsNotSent(t *testing.T) {
	spec := loadSpecs(t)["GetFunction"]
	spec.MissingRequired = []string{"Qualifier"}
	sent := 0
	engine := &Engine{
		Credentials: credentials.NewStaticCredentialsProvider("AKID", "s", ""), Partitions: testPartitions,
		HTTPClient: doFunc(func(*http.Request) (*http.Response, error) { sent++; return nil, io.EOF }),
	}
	answer := engine.Inspect(context.Background(), spec, "us-east-1", map[string]string{"FunctionName": "f"})
	if answer.Result != Unknown || sent != 0 || answer.Reason != "AWS transport or inspection failure" ||
		answer.Failure.Error() != "lambda:GetFunction failed: request not sent: required Qualifier not part of this lookup" {
		t.Fatalf("%d sent, %+v %v", sent, answer, answer.Failure)
	}
}
