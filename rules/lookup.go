package rules

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"

	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Wire protocols, named as Smithy names them.
const (
	AWSJSON10 = "awsJson1_0"
	AWSJSON11 = "awsJson1_1"
	RestJSON1 = "restJson1"
	RestXML   = "restXml"
	AWSQuery  = "awsQuery"
	EC2Query  = "ec2Query"
	RPCv2CBOR = "rpcv2Cbor"
)

// Input locations: where a request member goes on the wire.
const (
	InLabel  = "label"
	InQuery  = "query"
	InHeader = "header"
	InBody   = "body"
)

// Success modes: what a successful response must show to prove existence.
const (
	// SuccessEcho requires the identifier to come back in one of Paths.
	SuccessEcho = "identity_echo"
	// SuccessSingular treats any successful response as existence: the
	// operation reads exactly the one object it was given.
	SuccessSingular = "singular_success"
	// SuccessEchoOrSingular accepts either.
	SuccessEchoOrSingular = "identity_echo_or_singular_success"
)

// Spec is everything the generic engine in internal/awscall needs to send one
// existence lookup.
type Spec struct {
	Service   string `json:"service"`
	Operation string `json:"operation"`
	// Field is the request member that carries the identifier. With several
	// inputs it is the one a successful response must echo.
	Field string `json:"field"`

	// SigningName is the SigV4 service name the SDK signs with unless the
	// endpoint rules name another for a host.
	SigningName string `json:"signing_name"`
	// SDKID is the service's SDK ID, which names its endpoint settings, such
	// as AWS_ENDPOINT_URL_EC2.
	SDKID string `json:"sdk_id"`
	// Layout is how the SDK client is generated, "classic" or "schema"; they
	// read some malformed bodies differently, and the engine reads them as the
	// client would.
	Layout    string    `json:"sdk_layout"`
	Protocol  string    `json:"protocol"`
	Endpoints Endpoints `json:"endpoints"`

	// Method and Path are the HTTP request line. Path is a URI template for
	// the REST protocols and fixed otherwise.
	Method string `json:"method"`
	Path   string `json:"path"`
	// Target is the X-Amz-Target value for the awsJson protocols, and the
	// service shape name for rpcv2Cbor.
	Target string `json:"target,omitempty"`
	// APIVersion is the Version parameter of the query protocols.
	APIVersion string `json:"api_version,omitempty"`
	// Headers are constant request headers an SDK customization adds, such as
	// API Gateway's Accept: application/json.
	Headers map[string]string `json:"headers,omitempty"`
	// EndpointDiscovery is "optional" for an operation whose client discovers
	// its endpoint when discovery is enabled. The engine does not; see
	// Engine.Discovers.
	EndpointDiscovery string `json:"endpoint_discovery,omitempty"`

	// Inputs say where each request member goes on the wire.
	Inputs []Input `json:"inputs"`
	// MissingRequired are required members the lookup does not send. The SDK
	// refuses such a request before sending it, and so does the engine.
	MissingRequired []string `json:"missing_required,omitempty"`
	NotFound        Absence  `json:"not_found"`
	Success         Success  `json:"success"`

	// Verification records which live checks this spec passed against the SDK
	// adapters.
	Verification *Verification `json:"verification,omitempty"`
}

// Verification is what was checked live against the SDK adapters.
type Verification struct {
	Missing   bool `json:"missing"`
	Malformed bool `json:"malformed"`
	Exists    bool `json:"exists"`
	// ObservedOn lists the provider versions the checks were made on.
	ObservedOn []string `json:"observed_on,omitempty"`
}

// Input says where one request member goes on the wire.
type Input struct {
	// Member is the request member, by its SDK field name.
	Member   string `json:"member"`
	Location string `json:"location"`
	// Name is the wire name: the URI label, query key, header, or body key.
	Name string `json:"name"`
	// List sends the identifier as a one-element list.
	List bool `json:"list,omitempty"`
	// ListMember is the query-protocol list item key: "member" encodes
	// Name.member.1, empty encodes the flattened Name.1.
	ListMember string `json:"list_member,omitempty"`
	// Greedy labels keep "/" unescaped.
	Greedy bool `json:"greedy,omitempty"`
}

// Absence is what proves an identifier does not exist.
type Absence struct {
	// Codes are the rule's own wire error codes that mean the identifier does
	// not exist.
	Codes []string `json:"codes"`
	// Type is the modelled not-found error type, and TypeCodes every wire code
	// the SDK decodes into it. They are kept apart from Codes so the answer can
	// say which matched.
	Type      string   `json:"type,omitempty"`
	TypeCodes []string `json:"type_codes,omitempty"`
	// TypeNameMatches also accepts a code equal to Type itself, as the
	// dependency adapters do.
	TypeNameMatches bool `json:"type_name_matches,omitempty"`
	// StatusCodeFallback takes the code from the HTTP status text when an
	// error response has no body, as S3 does for HEAD requests.
	StatusCodeFallback bool `json:"status_code_fallback,omitempty"`
}

// Success says what a successful response must contain to prove existence.
type Success struct {
	Mode string `json:"mode"`
	// Paths lead from the response root to a value that must equal the
	// identifier. Lists are traversed implicitly; XML list wrappers such as
	// "item" or "member" are steps of their own.
	Paths [][]string `json:"paths,omitempty"`
}

// SpecSet is a lookup spec pack.
type SpecSet struct {
	Partitions []Partition `json:"partitions"`
	Specs      []Spec      `json:"specs"`
}

// Partition is one AWS partition as the SDK's partition data describes it.
// A region belongs to the partition that names it, else to the first whose
// RegionRegex matches, else to "aws".
type Partition struct {
	Name        string   `json:"name"`
	RegionRegex string   `json:"region_regex"`
	Regions     []string `json:"regions"`
}

// Endpoints are a service's endpoints as its SDK endpoint rules give them, for
// each combination of the FIPS and dual-stack settings.
type Endpoints struct {
	Standard      Endpoint `json:"standard"`
	FIPS          Endpoint `json:"fips"`
	DualStack     Endpoint `json:"dualstack"`
	FIPSDualStack Endpoint `json:"fips_dualstack"`
	// CustomRefuses names the settings, "fips" and "dualstack", that cannot be
	// combined with a configured endpoint URL.
	CustomRefuses []string `json:"custom_refuses,omitempty"`
	// UncheckedRegion is set for older clients, which pass any region to the
	// endpoint rules without checking it is a host name.
	UncheckedRegion bool `json:"unchecked_region,omitempty"`
}

// Endpoint is one variant's endpoints in every partition.
type Endpoint struct {
	// Partitions is the host for each partition, with {region} for the region. A
	// partition without an endpoint is absent.
	Partitions map[string]Host `json:"partitions"`
	// Regions are the named regions whose host differs from their
	// partition's.
	Regions map[string]Host `json:"regions,omitempty"`
	// Unavailable are the named regions the rules give no endpoint for.
	Unavailable []string `json:"unavailable,omitempty"`
}

// Host is one endpoint.
type Host struct {
	Hostname string `json:"hostname"`
	// SigningRegion is the region to sign for when it is not the request's,
	// as global services sign for us-east-1.
	SigningRegion string `json:"signing_region,omitempty"`
	// SigningName overrides the spec's signing name for this host.
	SigningName string `json:"signing_name,omitempty"`
}

var (
	regexMu sync.Mutex
	regexes = map[string]*regexp.Regexp{}
)

func compiled(expression string) *regexp.Regexp {
	regexMu.Lock()
	defer regexMu.Unlock()
	if re, ok := regexes[expression]; ok {
		return re
	}
	re, err := regexp.Compile(expression)
	if err != nil {
		// A pattern that cannot compile matches nothing, so the region falls
		// through to the default partition.
		re = regexp.MustCompile(`$^`)
	}
	regexes[expression] = re
	return re
}

// PartitionOf names the partition a region belongs to, chosen as the SDK
// chooses it: the partition naming the region, else the first whose pattern
// matches, else aws.
func PartitionOf(partitions []Partition, region string) string {
	for _, partition := range partitions {
		if slices.Contains(partition.Regions, region) {
			return partition.Name
		}
	}
	for _, partition := range partitions {
		if compiled(partition.RegionRegex).MatchString(region) {
			return partition.Name
		}
	}
	return "aws"
}

// Resolve picks the host for a region of the named partition.
func (e Endpoint) Resolve(partition, region string) (Host, error) {
	if host, found := e.Regions[region]; found {
		return host, nil
	}
	if slices.Contains(e.Unavailable, region) {
		return Host{}, fmt.Errorf("the endpoint rules give no endpoint for %s", region)
	}
	host, found := e.Partitions[partition]
	if !found {
		return Host{}, fmt.Errorf("the endpoint rules give no endpoint in partition %s", partition)
	}
	host.Hostname = strings.ReplaceAll(host.Hostname, "{region}", region)
	return host, nil
}

// Variant picks the endpoints for the FIPS and dual-stack settings.
func (e Endpoints) Variant(fips, dualStack bool) Endpoint {
	switch {
	case fips && dualStack:
		return e.FIPSDualStack
	case fips:
		return e.FIPS
	case dualStack:
		return e.DualStack
	}
	return e.Standard
}

// ValidRegion is the SDK's check of a configured region: dot-separated host
// labels.
func ValidRegion(region string) bool {
	for _, label := range strings.Split(region, ".") {
		if !smithyhttp.ValidHostLabel(label) || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

// MapFIPSRegion strips the legacy FIPS forms, fips-us-east-1 and
// us-east-1-fips, from a region, as the SDK does before resolving endpoints.
func MapFIPSRegion(region string) string {
	if strings.Contains(region, "-fips-") || strings.Contains(region, "fips-") || strings.Contains(region, "-fips") {
		region = strings.ReplaceAll(region, "-fips-", "-")
		region = strings.ReplaceAll(region, "fips-", "")
		region = strings.ReplaceAll(region, "-fips", "")
	}
	return region
}

// Target is where one lookup's requests go and how they are signed.
type Target struct {
	URL           *url.URL
	SigningName   string
	SigningRegion string
}

// EndpointSettings are what an SDK client's configuration says about endpoints.
type EndpointSettings struct {
	FIPS, DualStack bool
	BaseEndpoint    string
}

// ResolveTarget resolves where a lookup in region goes, as an SDK client with
// these settings would send it.
func ResolveTarget(spec Spec, partitions []Partition, region string, settings EndpointSettings) (Target, error) {
	if !spec.Endpoints.UncheckedRegion && !ValidRegion(region) {
		return Target{}, fmt.Errorf("invalid input region %s", region)
	}
	mapped := MapFIPSRegion(region)
	if custom := settings.BaseEndpoint; custom != "" {
		if settings.FIPS && slices.Contains(spec.Endpoints.CustomRefuses, "fips") || settings.DualStack && slices.Contains(spec.Endpoints.CustomRefuses, "dualstack") {
			return Target{}, fmt.Errorf("a configured endpoint URL cannot be combined with the FIPS or dual-stack setting")
		}
		base, err := url.Parse(custom)
		if err != nil {
			return Target{}, fmt.Errorf("configured endpoint URL does not parse")
		}
		return Target{URL: base, SigningName: spec.SigningName, SigningRegion: region}, nil
	}
	host, err := spec.Endpoints.Variant(settings.FIPS, settings.DualStack).Resolve(PartitionOf(partitions, mapped), mapped)
	if err != nil {
		return Target{}, err
	}
	// A host from the pack must be in AWS. Only an endpoint URL the user
	// configured may point anywhere else.
	if !AWSHost(host.Hostname) {
		return Target{}, fmt.Errorf("endpoint host %q is not in an AWS partition", host.Hostname)
	}
	resolved := Target{URL: &url.URL{Scheme: "https", Host: host.Hostname}, SigningName: spec.SigningName, SigningRegion: region}
	if host.SigningName != "" {
		resolved.SigningName = host.SigningName
	}
	if host.SigningRegion != "" {
		resolved.SigningRegion = host.SigningRegion
	}
	return resolved, nil
}
