package awscall

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/tfpreflight/tfpreflight/rules"
)

// sdkRecorder answers every request with one body and keeps the request.
type sdkRecorder struct {
	body string
	form url.Values
}

func (r *sdkRecorder) Do(request *http.Request) (*http.Response, error) {
	data, _ := io.ReadAll(request.Body)
	r.form, _ = url.ParseQuery(string(data))
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/xml"}}, Body: io.NopCloser(bytes.NewReader([]byte(r.body)))}, nil
}

const sdkSecurityGroups = `<DescribeSecurityGroupsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><requestId>r</requestId>
<securityGroupInfo><item><groupName>web</groupName><groupId>sg-1</groupId><vpcId>vpc-0123456789abcdef0</vpcId>
<ipPermissions><item><groups><item><groupName>other</groupName></item></groups></item></ipPermissions></item></securityGroupInfo></DescribeSecurityGroupsResponse>`

// The request the engine builds for the security group lookup must be the
// request the EC2 client builds for the same filters. This is what keeps the
// fixed filter names and the Filter.N numbering honest.
func TestSecurityGroupRequestIsWhatTheEC2ClientSends(t *testing.T) {
	recorder := &sdkRecorder{body: sdkSecurityGroups}
	client := ec2.New(ec2.Options{
		Region: "us-east-1", HTTPClient: recorder,
		Credentials: credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "secret", ""),
	})
	output, err := client.DescribeSecurityGroups(context.Background(), &ec2.DescribeSecurityGroupsInput{
		Filters: []types.Filter{
			{Name: aws.String("group-name"), Values: []string{"web"}},
			{Name: aws.String("vpc-id"), Values: []string{"vpc-0123456789abcdef0"}},
		},
		NextToken: aws.String("page-2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	sent := recorder.form

	// The lookup spec as the builder writes it: both filters, then the page input.
	built := securityGroupSpec()
	built.Inputs = append(built.Inputs, rules.Input{Member: "NextToken", Location: rules.InBody, Name: "NextToken", Page: true})
	built.Success.NextToken = []string{"nextToken"}
	if err := built.CheckListing(); err != nil {
		t.Fatal(err)
	}
	request, err := buildRequest(context.Background(), built, &url.URL{Scheme: "https", Host: "ec2.us-east-1.amazonaws.com"}, map[string]string{
		"GroupName": "web", "VpcId": "vpc-0123456789abcdef0", "NextToken": "page-2",
	})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(request.Body)
	ours, _ := url.ParseQuery(string(data))
	if !reflect.DeepEqual(sent, ours) {
		t.Fatalf("the engine sends %v\nthe EC2 client sends %v", ours, sent)
	}

	// The exact-name comparison reads the group's own name, not the names of the
	// groups its rules mention.
	if len(output.SecurityGroups) != 1 || aws.ToString(output.SecurityGroups[0].GroupName) != "web" {
		t.Fatalf("the EC2 client read %+v", output.SecurityGroups)
	}
	taken, _ := inspectListing(securityGroupSpec(), map[string]string{"GroupName": "web", "VpcId": "vpc-0123456789abcdef0"}, xmlOK(sdkSecurityGroups))
	if taken.Result != Exists {
		t.Errorf("the group the client lists as web = %s (%s), want EXISTS", taken.Result, taken.Reason)
	}
	// "other" is only named inside web's rules: it is not a group in this listing.
	other, _ := inspectListing(securityGroupSpec(), map[string]string{"GroupName": "other", "VpcId": "vpc-0123456789abcdef0"}, xmlOK(sdkSecurityGroups))
	if other.Result != NotFound {
		t.Errorf("a name that only appears in another group's rules = %s (%s), want NOT_FOUND", other.Result, other.Reason)
	}
}
