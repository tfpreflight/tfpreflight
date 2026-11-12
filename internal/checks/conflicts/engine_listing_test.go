package conflicts

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/tfpreflight/tfpreflight/internal/awscall"
	"github.com/tfpreflight/tfpreflight/rules"
)

// replyClient answers every request with one body and keeps what it was sent.
type replyClient struct {
	body string
	sent []string
}

func (c *replyClient) Do(request *http.Request) (*http.Response, error) {
	data, _ := io.ReadAll(request.Body)
	c.sent = append(c.sent, string(data))
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader([]byte(c.body)))}, nil
}

func listingAdapter(spec awscall.Spec, client *replyClient) LookupAdapter {
	standard := rules.Endpoint{Partitions: map[string]rules.Host{"aws": {Hostname: "svc.{region}.amazonaws.com"}}}
	spec.Endpoints = rules.Endpoints{Standard: standard, FIPS: standard, DualStack: standard, FIPSDualStack: standard}
	engine := &awscall.Engine{
		Credentials: credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "secret", ""),
		HTTPClient:  client, Region: "us-east-1",
		Partitions: []rules.Partition{{Name: "aws", RegionRegex: "^us-", Regions: []string{"us-east-1"}}},
	}
	return EngineAdapter(engine, spec)
}

func TestListingAdapterFillsOnlyTheIdentityInputs(t *testing.T) {
	logs := awscall.Spec{
		Service: "cloudwatchlogs", Operation: "DescribeLogGroups", Field: "LogGroupNamePrefix",
		SigningName: "logs", Protocol: rules.AWSJSON11, Target: "Logs_20140328.DescribeLogGroups", Path: "/",
		Inputs: []rules.Input{
			{Member: "LogGroupNamePrefix", Location: rules.InBody, Name: "logGroupNamePrefix"},
			{Member: "NextToken", Location: rules.InBody, Name: "nextToken", Page: true},
		},
		Success: rules.Success{Mode: rules.SuccessListExact, Paths: [][]string{{"logGroups", "logGroupName"}}, List: [][]string{{"logGroups"}}, NextToken: []string{"nextToken"}},
	}
	client := &replyClient{body: `{"logGroups":[{"logGroupName":"app-prod"}]}`}
	outcome, err := listingAdapter(logs, client).Lookup(context.Background(), LookupRequest{Operation: "DescribeLogGroups", Identity: "app"})
	if err != nil || outcome != OutcomeNotFound {
		t.Fatalf("a listing with only longer names = %s, %v; want not found", outcome, err)
	}
	if len(client.sent) != 1 || client.sent[0] != `{"logGroupNamePrefix":"app"}` {
		t.Fatalf("sent %v: the page input must not be taken for the identity", client.sent)
	}
	client = &replyClient{body: `{"logGroups":[{"logGroupName":"app"}]}`}
	if outcome, _ := listingAdapter(logs, client).Lookup(context.Background(), LookupRequest{Operation: "DescribeLogGroups", Identity: "app"}); outcome != OutcomeExists {
		t.Fatalf("the exact name = %s, want exists", outcome)
	}
}

func TestListingAdapterFillsEachPartOfAScopedIdentity(t *testing.T) {
	groups := awscall.Spec{
		Service: "ec2", Operation: "DescribeSecurityGroups", Field: "GroupName",
		SigningName: "ec2", Protocol: rules.EC2Query, APIVersion: "2016-11-15", Path: "/",
		Inputs: []rules.Input{
			{Member: "FilterGroupName", Location: rules.InBody, Name: "Filter.1.Name", Const: "group-name"},
			{Member: "GroupName", Location: rules.InBody, Name: "Filter.1.Value", List: true},
			{Member: "FilterVpcID", Location: rules.InBody, Name: "Filter.2.Name", Const: "vpc-id"},
			{Member: "VpcId", Location: rules.InBody, Name: "Filter.2.Value", List: true},
		},
		Success: rules.Success{Mode: rules.SuccessListExact, Paths: [][]string{{"securityGroupInfo", "item", "groupName"}}, List: [][]string{{"securityGroupInfo"}}},
	}
	client := &replyClient{body: `<R><securityGroupInfo><item><groupName>web</groupName></item></securityGroupInfo></R>`}
	outcome, err := listingAdapter(groups, client).Lookup(context.Background(), LookupRequest{
		Operation: "DescribeSecurityGroups", Values: map[string]string{"GroupName": "web", "VpcId": "vpc-0123456789abcdef0"},
	})
	if err != nil || outcome != OutcomeExists {
		t.Fatalf("got %s, %v; want exists", outcome, err)
	}
	for _, want := range []string{"Filter.1.Value.1=web", "Filter.2.Value.1=vpc-0123456789abcdef0", "Filter.2.Name=vpc-id"} {
		if !strings.Contains(client.sent[0], want) {
			t.Errorf("request %q is missing %s", client.sent[0], want)
		}
	}
}
