package rules

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAWSHost(t *testing.T) {
	for host, want := range map[string]bool{
		"dynamodb.us-east-1.amazonaws.com":   true,
		"iam.amazonaws.com":                  true,
		"s3.dualstack.eu-west-1.api.aws":     true,
		"ec2.cn-north-1.amazonaws.com.cn":    true,
		"ec2.us-iso-east-1.c2s.ic.gov":       true,
		"ec2.us-isof-south-1.csp.hci.ic.gov": true,
		"amazonaws.com":                      false,
		"evil.com":                           false,
		"amazonaws.com.evil.com":             false,
		"x.notamazonaws.com":                 false,
		"x.evil.com/.amazonaws.com":          false,
		"x.evil.com:443.amazonaws.com":       false,
		"X.AMAZONAWS.COM":                    false,
		"user@x.amazonaws.com":               false,
		"-x.amazonaws.com":                   false,
		"x..amazonaws.com":                   false,
	} {
		if got := AWSHost(host); got != want {
			t.Errorf("AWSHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestCheckReadOnly(t *testing.T) {
	host := Endpoints{Standard: Endpoint{Partitions: map[string]Host{"aws": {Hostname: "svc.{region}.amazonaws.com"}}}}
	for name, tc := range map[string]struct {
		spec Spec
		want string
	}{
		"REST GET":              {Spec{Operation: "GetThing", Protocol: RestJSON1, Method: "GET", Endpoints: host}, ""},
		"REST HEAD":             {Spec{Operation: "HeadBucket", Protocol: RestXML, Method: "HEAD", Endpoints: host}, ""},
		"REST POST allowlisted": {Spec{Service: "ivs", Operation: "GetRecordingConfiguration", Protocol: RestJSON1, Method: "POST", Endpoints: host}, ""},
		"REST POST other":       {Spec{Service: "ivs", Operation: "GetChannel", Protocol: RestJSON1, Method: "POST", Endpoints: host}, "not an allowed read"},
		"REST no method":        {Spec{Operation: "GetThing", Protocol: RestJSON1, Endpoints: host}, "not an allowed read"},
		"REST DELETE":           {Spec{Operation: "GetThing", Protocol: RestJSON1, Method: "DELETE", Endpoints: host}, "not an allowed read"},
		"JSON":                  {Spec{Operation: "DescribeTable", Protocol: AWSJSON10, Method: "POST", Path: "/", Target: "DynamoDB_20120810.DescribeTable", Endpoints: host}, ""},
		"JSON other target":     {Spec{Operation: "DescribeTable", Protocol: AWSJSON10, Method: "POST", Target: "DynamoDB_20120810.DeleteTable", Endpoints: host}, "does not name"},
		"JSON GET":              {Spec{Operation: "DescribeTable", Protocol: AWSJSON10, Method: "GET", Target: "X.DescribeTable", Endpoints: host}, "not allowed"},
		"query path":            {Spec{Operation: "DescribeVpcs", Protocol: EC2Query, Method: "POST", Path: "/?Action=DeleteVpc", Endpoints: host}, "path"},
		"CBOR":                  {Spec{Operation: "DescribeBuild", Protocol: RPCv2CBOR, Method: "POST", Path: "/", Endpoints: host}, ""},
		"write operation":       {Spec{Operation: "DeleteThing", Protocol: RestJSON1, Method: "GET", Endpoints: host}, "not a read"},
		"prefix only in word":   {Spec{Operation: "Listener", Protocol: RestJSON1, Method: "GET", Endpoints: host}, "not a read"},
		"unknown protocol":      {Spec{Operation: "GetThing", Protocol: "smithyRpc", Method: "POST", Endpoints: host}, "unknown protocol"},
		"Accept header":         {Spec{Operation: "GetThing", Protocol: RestJSON1, Method: "GET", Headers: map[string]string{"accept": "application/json"}, Endpoints: host}, ""},
		"other header":          {Spec{Operation: "GetThing", Protocol: RestJSON1, Method: "GET", Headers: map[string]string{"X-Http-Method-Override": "DELETE"}, Endpoints: host}, "not allowed"},
		"FIPS host":             {Spec{Operation: "GetThing", Protocol: RestJSON1, Method: "GET", Endpoints: Endpoints{FIPS: Endpoint{Regions: map[string]Host{"us-east-1": {Hostname: "evil.example.net"}}}}}, "not in an AWS partition"},
	} {
		t.Run(name, func(t *testing.T) {
			err := tc.spec.CheckReadOnly()
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// A range pack is checked entry by entry, so a bad spec on any one version
// fails the whole pack.
func TestRangePackCheckSpecs(t *testing.T) {
	good := `{"operation":"GetThing","protocol":"restJson1","method":"GET","endpoints":{"standard":{"partitions":{"aws":{"hostname":"svc.{region}.amazonaws.com"}}}}}`
	bad := strings.Replace(good, "GetThing", "DeleteThing", 1)
	pack := func(entries ...string) *RangePack {
		p := &RangePack{Name: "aws/lookup/specs-{provider_version}.json", Versions: []string{"1.0.0", "1.1.0"}}
		field := RangeField{Name: "specs", Kind: FieldList}
		for _, e := range entries {
			field.Entries = append(field.Entries, RangeEntry{Versions: []VersionRange{{"1.1.0", "1.1.0"}}, Value: json.RawMessage(e)})
		}
		p.Fields = []RangeField{field}
		return p
	}
	if err := pack(good).CheckSpecs(); err != nil {
		t.Fatal(err)
	}
	if err := pack(good, bad).CheckSpecs(); err == nil || !strings.Contains(err.Error(), "DeleteThing") {
		t.Fatalf("err = %v", err)
	}
}
