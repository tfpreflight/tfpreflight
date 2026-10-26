package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// tfpreflight only reads AWS, and this gate holds every lookup spec to that in
// code: a spec that could send anything but a read, or send it outside AWS,
// fails to load and is never sent.

var readOperation = regexp.MustCompile(`^(Describe|Get|List|Head|BatchGet|Query|Search|Lookup)([A-Z]|$)`)

// restPOSTReads are the REST operations AWS models as POST although they only
// read. Each one is listed by hand; a new one is a reviewed code change.
var restPOSTReads = map[string]bool{
	"appflow:DescribeFlow":            true,
	"ivs:GetRecordingConfiguration":   true,
	"ivschat:GetLoggingConfiguration": true,
	"kinesisvideo:DescribeStream":     true,
	"lakeformation:DescribeResource":  true,
	"oam:GetSink":                     true,
	"resourcegroups:GetGroup":         true,
	"worklink:DescribeFleetMetadata":  true,
}

// constantHeaders are the request headers a spec may add. Any other could
// change which operation AWS runs, as X-Amz-Target does.
var constantHeaders = map[string]bool{"Accept": true}

// awsDNSSuffixes are the AWS partitions' DNS suffixes, standard and dual-stack,
// from the SDK's partition data.
var awsDNSSuffixes = []string{
	"amazonaws.com", "api.aws",
	"amazonaws.com.cn", "api.amazonwebservices.com.cn",
	"amazonaws.eu", "api.amazonwebservices.eu",
	"c2s.ic.gov", "api.aws.ic.gov",
	"sc2s.sgov.gov", "api.aws.scloud",
	"cloud.adc-e.uk", "api.cloud-aws.adc-e.uk",
	"csp.hci.ic.gov", "api.aws.hci.ic.gov",
}

// AWSHost reports whether host is a DNS name in an AWS partition.
func AWSHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	for _, suffix := range awsDNSSuffixes {
		if strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

// CheckReadOnly reports why a spec could send something other than a read, or
// send it outside AWS.
func (s Spec) CheckReadOnly() error {
	if !readOperation.MatchString(s.Operation) {
		return fmt.Errorf("operation %q is not a read", s.Operation)
	}
	if err := s.checkWire(); err != nil {
		return err
	}
	for name := range s.Headers {
		if !constantHeaders[http.CanonicalHeaderKey(name)] {
			return fmt.Errorf("constant header %q is not allowed", name)
		}
	}
	return s.Endpoints.checkHosts()
}

// checkWire checks the method, and the request fields that name the operation.
func (s Spec) checkWire() error {
	method := s.Method
	if method == "" {
		method = http.MethodPost
	}
	switch s.Protocol {
	case RestJSON1, RestXML:
		if method == http.MethodGet || method == http.MethodHead {
			return nil
		}
		if method == http.MethodPost && restPOSTReads[s.Service+":"+s.Operation] {
			return nil
		}
		return fmt.Errorf("%s %s is not an allowed read for %s", method, s.Operation, s.Protocol)
	case AWSJSON10, AWSJSON11, AWSQuery, EC2Query, RPCv2CBOR:
		if method != http.MethodPost {
			return fmt.Errorf("method %s is not allowed for %s", method, s.Protocol)
		}
		if s.Path != "" && s.Path != "/" {
			return fmt.Errorf("path %q is not allowed for %s", s.Path, s.Protocol)
		}
		if (s.Protocol == AWSJSON10 || s.Protocol == AWSJSON11) && !strings.HasSuffix(s.Target, "."+s.Operation) {
			return fmt.Errorf("target %q does not name operation %s", s.Target, s.Operation)
		}
		return nil
	}
	return fmt.Errorf("unknown protocol %q", s.Protocol)
}

// checkHosts checks every host of every variant. {region} is the only
// placeholder a host may hold.
func (e Endpoints) checkHosts() error {
	for _, endpoint := range []Endpoint{e.Standard, e.FIPS, e.DualStack, e.FIPSDualStack} {
		for _, hosts := range []map[string]Host{endpoint.Partitions, endpoint.Regions} {
			for _, host := range hosts {
				if !AWSHost(strings.ReplaceAll(host.Hostname, "{region}", "us-east-1")) {
					return fmt.Errorf("endpoint host %q is not in an AWS partition", host.Hostname)
				}
			}
		}
	}
	return nil
}

// Check holds every spec in the set to CheckReadOnly.
func (s SpecSet) Check() error {
	var problems []error
	for _, spec := range s.Specs {
		if err := spec.CheckReadOnly(); err != nil {
			problems = append(problems, fmt.Errorf("%s:%s: %w", spec.Service, spec.Operation, err))
		}
	}
	return errors.Join(problems...)
}

// CheckSpecs holds every spec a lookup range pack stores to CheckReadOnly. Each
// stored spec covers every version it holds for, so nothing has to be
// materialized.
func (p *RangePack) CheckSpecs() error {
	var problems []error
	for _, field := range p.Fields {
		if field.Name != "specs" {
			continue
		}
		for _, entry := range field.Entries {
			var set SpecSet
			var err error
			if field.Kind == FieldValue {
				err = json.Unmarshal(entry.Value, &set.Specs)
			} else {
				var spec Spec
				err = json.Unmarshal(entry.Value, &spec)
				set.Specs = []Spec{spec}
			}
			if err == nil {
				err = set.Check()
			}
			if err != nil {
				problems = append(problems, err)
			}
		}
	}
	return errors.Join(problems...)
}
