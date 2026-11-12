package awscall

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tfpreflight/tfpreflight/rules"
)

func listingPartitions() []rules.Partition {
	return []rules.Partition{{Name: "aws", RegionRegex: "^us-", Regions: []string{"us-east-1"}}}
}

func listingEndpoints(host string) rules.Endpoints {
	standard := rules.Endpoint{Partitions: map[string]rules.Host{"aws": {Hostname: host}}}
	return rules.Endpoints{Standard: standard, FIPS: standard, DualStack: standard, FIPSDualStack: standard}
}

// logGroupSpec is the name lookup for a CloudWatch log group: list the groups
// whose name starts with the planned name, and look for the exact name.
func logGroupSpec() Spec {
	return Spec{
		Service: "cloudwatchlogs", Operation: "DescribeLogGroups", Field: "LogGroupNamePrefix",
		SigningName: "logs", Protocol: rules.AWSJSON11, Target: "Logs_20140328.DescribeLogGroups", Path: "/",
		Endpoints: listingEndpoints("logs.{region}.amazonaws.com"),
		Inputs: []rules.Input{
			{Member: "LogGroupNamePrefix", Location: rules.InBody, Name: "logGroupNamePrefix"},
			{Member: "NextToken", Location: rules.InBody, Name: "nextToken", Page: true},
		},
		Success: rules.Success{
			Mode:      rules.SuccessListExact,
			Paths:     [][]string{{"logGroups", "logGroupName"}},
			List:      [][]string{{"logGroups"}},
			NextToken: []string{"nextToken"},
		},
	}
}

// securityGroupSpec is the name lookup for a security group in one VPC, with
// both conditions sent as fixed-name filters.
func securityGroupSpec() Spec {
	return Spec{
		Service: "ec2", Operation: "DescribeSecurityGroups", Field: "GroupName",
		SigningName: "ec2", Protocol: rules.EC2Query, APIVersion: "2016-11-15", Path: "/",
		Endpoints: listingEndpoints("ec2.{region}.amazonaws.com"),
		Inputs: []rules.Input{
			{Member: "FilterGroupName", Location: rules.InBody, Name: "Filter.1.Name", Const: "group-name"},
			{Member: "GroupName", Location: rules.InBody, Name: "Filter.1.Value", List: true},
			{Member: "FilterVpcID", Location: rules.InBody, Name: "Filter.2.Name", Const: "vpc-id"},
			{Member: "VpcId", Location: rules.InBody, Name: "Filter.2.Value", List: true},
		},
		Success: rules.Success{
			Mode:  rules.SuccessListExact,
			Paths: [][]string{{"securityGroupInfo", "item", "groupName"}},
			List:  [][]string{{"securityGroupInfo"}},
		},
	}
}

func jsonOK(body string) recorded {
	return recorded{Status: 200, Body: &body, Headers: map[string]string{"Content-Type": "application/x-amz-json-1.1"}}
}

func xmlOK(body string) recorded {
	return recorded{Status: 200, Body: &body, Headers: map[string]string{"Content-Type": "text/xml"}}
}

func inspectListing(spec Spec, values map[string]string, responses ...recorded) (Answer, *fakeClient) {
	var slept []time.Duration
	client := &fakeClient{responses: responses}
	engine := testEngine(client, &slept)
	engine.Partitions = listingPartitions()
	return engine.Inspect(context.Background(), spec, "us-east-1", values), client
}

func TestLogGroupListing(t *testing.T) {
	values := map[string]string{"LogGroupNamePrefix": "app"}
	cases := []struct {
		name      string
		responses []recorded
		want      Result
		requests  int
	}{
		{"the exact name is listed", []recorded{jsonOK(`{"logGroups":[{"logGroupName":"app"},{"logGroupName":"app-prod"}]}`)}, Exists, 1},
		{"only longer names share the prefix", []recorded{jsonOK(`{"logGroups":[{"logGroupName":"app-prod"},{"logGroupName":"app2"}]}`)}, NotFound, 1},
		{"nothing is listed", []recorded{jsonOK(`{"logGroups":[]}`)}, NotFound, 1},
		{"a different case is a different name", []recorded{jsonOK(`{"logGroups":[{"logGroupName":"App"}]}`)}, NotFound, 1},
		{"the exact name is on the second page", []recorded{
			jsonOK(`{"logGroups":[{"logGroupName":"app-a"}],"nextToken":"t1"}`),
			jsonOK(`{"logGroups":[{"logGroupName":"app"}]}`),
		}, Exists, 2},
		{"the last page has no exact name", []recorded{
			jsonOK(`{"logGroups":[{"logGroupName":"app-a"}],"nextToken":"t1"}`),
			jsonOK(`{"logGroups":[{"logGroupName":"app-b"}]}`),
		}, NotFound, 2},
		{"a response that is not a listing proves nothing", []recorded{jsonOK(`{}`)}, Unknown, 1},
		{"a null list proves nothing", []recorded{jsonOK(`{"logGroups":null}`)}, Unknown, 1},
		{"an empty token is no token", []recorded{jsonOK(`{"logGroups":[],"nextToken":""}`)}, NotFound, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			answer, client := inspectListing(logGroupSpec(), values, c.responses...)
			if answer.Result != c.want {
				t.Fatalf("got %s (%s), want %s", answer.Result, answer.Reason, c.want)
			}
			if len(client.requests) != c.requests {
				t.Fatalf("%d requests, want %d", len(client.requests), c.requests)
			}
		})
	}
}

func TestLogGroupListingRequests(t *testing.T) {
	_, client := inspectListing(logGroupSpec(), map[string]string{"LogGroupNamePrefix": "app"},
		jsonOK(`{"logGroups":[{"logGroupName":"app-a"}],"nextToken":"t1"}`),
		jsonOK(`{"logGroups":[]}`))
	if got := string(client.bodies[0]); got != `{"logGroupNamePrefix":"app"}` {
		t.Errorf("first request body = %s: it must carry no empty token", got)
	}
	if got := string(client.bodies[1]); got != `{"logGroupNamePrefix":"app","nextToken":"t1"}` {
		t.Errorf("second request body = %s", got)
	}
}

func TestListingStopsAtThePageLimit(t *testing.T) {
	answer, client := inspectListing(logGroupSpec(), map[string]string{"LogGroupNamePrefix": "app"},
		jsonOK(`{"logGroups":[{"logGroupName":"app-a"}],"nextToken":"again"}`))
	if answer.Result != Unknown {
		t.Fatalf("an endless listing = %s, want UNKNOWN", answer.Result)
	}
	if len(client.requests) != maxListingPages {
		t.Fatalf("%d requests, want the limit %d", len(client.requests), maxListingPages)
	}
	if answer.Failure == nil {
		t.Error("an unanswered lookup must say why")
	}
}

func TestListingErrorsAreNotAbsence(t *testing.T) {
	denied := recorded{Status: 400, Body: strPtr(`{"__type":"AccessDeniedException","message":"no"}`), Headers: map[string]string{"Content-Type": "application/x-amz-json-1.1"}}
	answer, _ := inspectListing(logGroupSpec(), map[string]string{"LogGroupNamePrefix": "app"}, denied)
	if answer.Result != Unknown {
		t.Fatalf("a denied listing = %s, want UNKNOWN", answer.Result)
	}
}

func strPtr(s string) *string { return &s }

func TestSecurityGroupListing(t *testing.T) {
	values := map[string]string{"GroupName": "web", "VpcId": "vpc-0123456789abcdef0"}
	item := func(name string) string {
		return fmt.Sprintf(`<item><groupName>%s</groupName><vpcId>vpc-0123456789abcdef0</vpcId></item>`, name)
	}
	wrap := func(items ...string) recorded {
		return xmlOK(`<DescribeSecurityGroupsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><requestId>r</requestId><securityGroupInfo>` + strings.Join(items, "") + `</securityGroupInfo></DescribeSecurityGroupsResponse>`)
	}
	cases := []struct {
		name     string
		response recorded
		want     Result
	}{
		{"the name is taken in the VPC", wrap(item("web")), Exists},
		{"no group matches the filters", wrap(), NotFound},
		{"a wildcard match is not the name", wrap(item("web-1")), NotFound},
		{"no listing in the response", xmlOK(`<DescribeSecurityGroupsResponse><requestId>r</requestId></DescribeSecurityGroupsResponse>`), Unknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			answer, _ := inspectListing(securityGroupSpec(), values, c.response)
			if answer.Result != c.want {
				t.Fatalf("got %s (%s), want %s", answer.Result, answer.Reason, c.want)
			}
		})
	}
}

func TestSecurityGroupRequestCarriesBothFilters(t *testing.T) {
	_, client := inspectListing(securityGroupSpec(), map[string]string{"GroupName": "web", "VpcId": "vpc-0123456789abcdef0"},
		xmlOK(`<DescribeSecurityGroupsResponse><securityGroupInfo/></DescribeSecurityGroupsResponse>`))
	body := string(client.bodies[0])
	for _, want := range []string{"Action=DescribeSecurityGroups", "Filter.1.Name=group-name", "Filter.1.Value.1=web", "Filter.2.Name=vpc-id", "Filter.2.Value.1=vpc-0123456789abcdef0"} {
		if !strings.Contains(body, want) {
			t.Errorf("request %q is missing %s", body, want)
		}
	}
}

// A binary from before the mode existed reads it as an unknown mode: it must
// still answer "exists" for an exact match and must never answer "free".
func TestABinaryThatDoesNotKnowTheModeNeverAnswersFree(t *testing.T) {
	old := logGroupSpec()
	old.Success.Mode = "a_mode_from_the_future"
	values := map[string]string{"LogGroupNamePrefix": "app"}
	for name, c := range map[string]struct {
		response recorded
		want     Result
	}{
		"exact match":             {jsonOK(`{"logGroups":[{"logGroupName":"app"}]}`), Exists},
		"only longer names":       {jsonOK(`{"logGroups":[{"logGroupName":"app-prod"}]}`), Unknown},
		"empty listing":           {jsonOK(`{"logGroups":[]}`), Unknown},
		"listing with more pages": {jsonOK(`{"logGroups":[{"logGroupName":"app-a"}],"nextToken":"t"}`), Unknown},
	} {
		t.Run(name, func(t *testing.T) {
			answer, client := inspectListing(old, values, c.response)
			if answer.Result != c.want {
				t.Fatalf("got %s (%s), want %s", answer.Result, answer.Reason, c.want)
			}
			if len(client.requests) != 1 {
				t.Fatalf("%d requests: an unknown mode reads one page", len(client.requests))
			}
		})
	}
}

func TestListingSpecsAreChecked(t *testing.T) {
	good := logGroupSpec()
	if err := (rules.SpecSet{Specs: []rules.Spec{good, securityGroupSpec()}}).Check(); err != nil {
		t.Fatalf("a correct listing spec was refused: %v", err)
	}
	noList := logGroupSpec()
	noList.Success.List = nil
	tokenWithoutInput := logGroupSpec()
	tokenWithoutInput.Inputs = tokenWithoutInput.Inputs[:1]
	inputWithoutToken := logGroupSpec()
	inputWithoutToken.Success.NextToken = nil
	for name, spec := range map[string]rules.Spec{"no list": noList, "token without a page input": tokenWithoutInput, "page input without a token": inputWithoutToken} {
		if err := (rules.SpecSet{Specs: []rules.Spec{spec}}).Check(); err == nil {
			t.Errorf("%s: the spec was accepted", name)
		}
	}
}
