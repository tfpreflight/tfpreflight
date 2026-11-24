package awscall

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/rules"
)

type recorded struct {
	Operation string            `json:"operation"`
	Scenario  string            `json:"scenario"`
	Status    int               `json:"status"`
	Headers   map[string]string `json:"headers"`
	Body      *string           `json:"body"`
	CBOR      any               `json:"cbor"`
}

func loadSpecs(t *testing.T) map[string]Spec {
	t.Helper()
	data, err := os.ReadFile("testdata/specs.json")
	if err != nil {
		t.Fatal(err)
	}
	var set SpecSet
	if err := json.Unmarshal(data, &set); err != nil {
		t.Fatal(err)
	}
	testPartitions = set.Partitions
	byOperation := map[string]Spec{}
	for _, spec := range set.Specs {
		byOperation[spec.Operation] = spec
	}
	return byOperation
}

// testPartitions are the partitions of the spec pack the test loaded.
var testPartitions []rules.Partition

func loadResponses(t *testing.T) map[string]map[string]recorded {
	t.Helper()
	data, err := os.ReadFile("testdata/responses.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Responses []recorded `json:"responses"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]recorded{}
	for _, r := range file.Responses {
		if out[r.Operation] == nil {
			out[r.Operation] = map[string]recorded{}
		}
		out[r.Operation][r.Scenario] = r
	}
	return out
}

// testCBOR encodes the response fixtures, which nest maps in lists.
func testCBOR(value any) []byte {
	var out []byte
	head := func(major byte, n int) {
		switch {
		case n < 24:
			out = append(out, major<<5|byte(n))
		case n < 256:
			out = append(out, major<<5|24, byte(n))
		default:
			out = append(out, major<<5|25, byte(n>>8), byte(n))
		}
	}
	var write func(any)
	write = func(v any) {
		switch v := v.(type) {
		case string:
			head(3, len(v))
			out = append(out, v...)
		case []any:
			head(4, len(v))
			for _, item := range v {
				write(item)
			}
		case map[string]any:
			keys := make([]string, 0, len(v))
			for key := range v {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			head(5, len(keys))
			for _, key := range keys {
				write(key)
				write(v[key])
			}
		}
	}
	write(value)
	return out
}

func (r recorded) response() *http.Response {
	body := []byte{}
	if r.CBOR != nil {
		body = testCBOR(r.CBOR)
	} else if r.Body != nil {
		body = []byte(*r.Body)
	}
	header := http.Header{}
	for key, value := range r.Headers {
		header.Set(key, value)
	}
	return &http.Response{StatusCode: r.Status, Header: header, Body: io.NopCloser(bytes.NewReader(body))}
}

type fakeClient struct {
	responses []recorded
	requests  []*http.Request
	bodies    [][]byte
}

func (f *fakeClient) Do(request *http.Request) (*http.Response, error) {
	body := []byte{}
	if request.Body != nil {
		body, _ = io.ReadAll(request.Body)
	}
	f.requests = append(f.requests, request)
	f.bodies = append(f.bodies, body)
	next := f.responses[0]
	if len(f.responses) > 1 {
		f.responses = f.responses[1:]
	}
	return next.response(), nil
}

func testEngine(client *fakeClient, slept *[]time.Duration) *Engine {
	return &Engine{
		Credentials: credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "secret", ""),
		HTTPClient:  client,
		Partitions:  testPartitions,
		Now:         func() time.Time { return time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC) },
		Sleep: func(_ context.Context, d time.Duration) error {
			*slept = append(*slept, d)
			return nil
		},
	}
}

var identifiers = map[string]string{
	"DescribeVpcs":            "vpc-0123456789abcdef0",
	"GetRole":                 "app-role",
	"DescribeCertificate":     "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
	"DescribeTable":           "orders",
	"GetFunction":             "my-function",
	"GetDistribution":         "E2EXAMPLE",
	"DescribeFleetAttributes": "fleet-123",
}

// Every protocol, every outcome: only an authoritative not-found code is
// NOT_FOUND, and anything uncertain is UNKNOWN.
func TestEveryProtocolEveryOutcome(t *testing.T) {
	specs, responses := loadSpecs(t), loadResponses(t)
	protocols := map[string]bool{}
	for operation, spec := range specs {
		protocols[spec.Protocol] = true
		check := protocolCheck{operation: operation, spec: spec, responses: responses[operation], id: identifiers[operation]}
		check.singleAnswers(t)
		check.echoRequired(t)
		check.throttledThenSuccess(t)
		check.alwaysThrottled(t)
	}
	if len(protocols) != 7 {
		t.Fatalf("fixtures cover %d protocols, want 7", len(protocols))
	}
}

// protocolCheck replays one operation's recorded scenarios.
type protocolCheck struct {
	operation string
	spec      Spec
	responses map[string]recorded
	id        string
}

func (c protocolCheck) lookup(responses ...recorded) (Result, string, *fakeClient, []time.Duration) {
	var slept []time.Duration
	client := &fakeClient{responses: responses}
	got, reason := testEngine(client, &slept).Lookup(context.Background(), c.spec, "us-east-1", c.id)
	return got, reason, client, slept
}

// singleAnswers checks each non-retryable answer is reached in one request.
func (c protocolCheck) singleAnswers(t *testing.T) {
	for scenario, want := range map[string]Result{
		"success": Exists, "not_found": NotFound, "access_denied": Unknown, "malformed": Unknown,
	} {
		t.Run(c.spec.Protocol+"/"+scenario, func(t *testing.T) {
			got, reason, client, _ := c.lookup(c.responses[scenario])
			if got != want {
				t.Fatalf("%s %s = %s (%s), want %s", c.operation, scenario, got, reason, want)
			}
			if len(client.requests) != 1 {
				t.Fatalf("%d requests for a non-retryable answer", len(client.requests))
			}
		})
	}
}

// echoRequired checks a success that does not echo the identifier proves
// nothing, where the fixtures record one.
func (c protocolCheck) echoRequired(t *testing.T) {
	echoOnly, ok := c.responses["success_without_echo"]
	if !ok {
		return
	}
	if got, reason, _, _ := c.lookup(echoOnly); got != Unknown {
		t.Errorf("%s: a success that does not echo the identifier = %s (%s), want UNKNOWN", c.operation, got, reason)
	}
}

func (c protocolCheck) throttledThenSuccess(t *testing.T) {
	t.Run(c.spec.Protocol+"/throttled_then_success", func(t *testing.T) {
		got, reason, client, slept := c.lookup(c.responses["throttled"], c.responses["success"])
		if got != Exists || len(client.requests) != 2 || len(slept) != 1 {
			t.Fatalf("%s: got %s (%s) after %d requests and %d waits", c.operation, got, reason, len(client.requests), len(slept))
		}
	})
}

func (c protocolCheck) alwaysThrottled(t *testing.T) {
	t.Run(c.spec.Protocol+"/always_throttled", func(t *testing.T) {
		got, _, client, slept := c.lookup(c.responses["throttled"])
		if got != Unknown || len(client.requests) != 3 || len(slept) != 2 {
			t.Fatalf("%s: got %s after %d requests and %d waits; want UNKNOWN after 3", c.operation, got, len(client.requests), len(slept))
		}
		for attempt, delay := range slept {
			if limit := time.Duration(1<<(attempt+1)) * time.Second; delay < 0 || delay > limit {
				t.Fatalf("wait %d = %s, beyond %s", attempt+1, delay, limit)
			}
		}
	})
}

// Each protocol puts the identifier where AWS expects it, and every request
// is signed for the right service and region.
func TestRequestEncoding(t *testing.T) {
	specs, responses := loadSpecs(t), loadResponses(t)
	for operation, check := range map[string]func(*testing.T, *http.Request, []byte){
		"DescribeVpcs": func(t *testing.T, r *http.Request, body []byte) {
			form, _ := url.ParseQuery(string(body))
			expect(t, r.URL.Host == "ec2.us-east-1.amazonaws.com" && r.Method == "POST" && form.Get("Action") == "DescribeVpcs" &&
				form.Get("Version") == "2016-11-15" && form.Get("VpcId.1") == identifiers["DescribeVpcs"], r, body)
		},
		"GetRole": func(t *testing.T, r *http.Request, body []byte) {
			form, _ := url.ParseQuery(string(body))
			expect(t, r.URL.Host == "iam.amazonaws.com" && form.Get("Action") == "GetRole" && form.Get("RoleName") == "app-role", r, body)
		},
		"DescribeCertificate": func(t *testing.T, r *http.Request, body []byte) {
			expect(t, r.Header.Get("X-Amz-Target") == "CertificateManager.DescribeCertificate" && r.Header.Get("Content-Type") == "application/x-amz-json-1.1" &&
				string(body) == `{"CertificateArn":"`+identifiers["DescribeCertificate"]+`"}`, r, body)
		},
		"DescribeTable": func(t *testing.T, r *http.Request, body []byte) {
			expect(t, r.Header.Get("X-Amz-Target") == "DynamoDB_20120810.DescribeTable" && r.Header.Get("Content-Type") == "application/x-amz-json-1.0" &&
				string(body) == `{"TableName":"orders"}`, r, body)
		},
		"GetFunction": func(t *testing.T, r *http.Request, body []byte) {
			expect(t, r.Method == "GET" && r.URL.EscapedPath() == "/2015-03-31/functions/my-function" && len(body) == 0, r, body)
		},
		"GetDistribution": func(t *testing.T, r *http.Request, body []byte) {
			expect(t, r.URL.Host == "cloudfront.amazonaws.com" && r.Method == "GET" && r.URL.EscapedPath() == "/2020-05-31/distribution/E2EXAMPLE", r, body)
		},
		"DescribeFleetAttributes": func(t *testing.T, r *http.Request, body []byte) {
			decoded, err := decodeCBOR(body)
			fields, _ := decoded.(map[string]any)
			ids, _ := fields["FleetIds"].([]any)
			expect(t, err == nil && r.URL.Path == "/service/GameLift/operation/DescribeFleetAttributes" &&
				r.Header.Get("Smithy-Protocol") == "rpc-v2-cbor" && len(ids) == 1 && ids[0] == "fleet-123", r, body)
		},
	} {
		spec := specs[operation]
		t.Run(spec.Protocol, func(t *testing.T) {
			var slept []time.Duration
			client := &fakeClient{responses: []recorded{responses[operation]["success"]}}
			testEngine(client, &slept).Lookup(context.Background(), spec, "us-east-1", identifiers[operation])
			request := client.requests[0]
			scope := "/20261012/us-east-1/" + spec.SigningName + "/aws4_request"
			if !strings.Contains(request.Header.Get("Authorization"), "Credential=AKIDEXAMPLE"+scope) {
				t.Fatalf("signature scope: %s", request.Header.Get("Authorization"))
			}
			check(t, request, client.bodies[0])
		})
	}
}

func expect(t *testing.T, ok bool, r *http.Request, body []byte) {
	t.Helper()
	if !ok {
		t.Fatalf("request %s %s headers %v body %q", r.Method, r.URL, r.Header, body)
	}
}

// Endpoints are chosen as an SDK client chooses them: a global service signs
// for its home region whatever region was asked for, every partition has its
// own hosts, the FIPS and dual-stack settings pick other hosts, and a
// configured endpoint URL replaces the host and prefixes the path.
func TestEndpoints(t *testing.T) {
	specs := loadSpecs(t)
	assertPartitionEndpoints(t, specs)
	assertEndpointsFromEnvironment(t, specs)
	// A lookup naming no region uses the configured one.
	var slept []time.Duration
	client := &fakeClient{responses: []recorded{{Status: 400}}}
	engine := testEngine(client, &slept)
	engine.Region = "eu-west-1"
	engine.Lookup(context.Background(), specs["DescribeVpcs"], "", "vpc-1")
	if len(client.requests) != 1 || client.requests[0].URL.Host != "ec2.eu-west-1.amazonaws.com" {
		t.Errorf("no region: %d requests", len(client.requests))
	}
}

// endpointTarget is where an operation in region goes, as "URL name/region",
// or "error: ..." when the engine cannot say.
func endpointTarget(t *testing.T, specs map[string]Spec, engine *Engine, operation, region string) string {
	t.Helper()
	where, err := engine.Target(specs[operation], region)
	if err != nil {
		return "error: " + err.Error()
	}
	return where.URL.String() + " " + where.SigningName + "/" + where.SigningRegion
}

func assertPartitionEndpoints(t *testing.T, specs map[string]Spec) {
	t.Helper()
	plain := &Engine{Partitions: testPartitions}
	for _, c := range []struct{ operation, region, want string }{
		{"GetRole", "eu-west-1", "https://iam.amazonaws.com iam/us-east-1"},
		{"DescribeVpcs", "ap-southeast-2", "https://ec2.ap-southeast-2.amazonaws.com ec2/ap-southeast-2"},
		{"DescribeVpcs", "cn-north-1", "https://ec2.cn-north-1.amazonaws.com.cn ec2/cn-north-1"},
		{"DescribeVpcs", "us-gov-west-1", "https://ec2.us-gov-west-1.amazonaws.com ec2/us-gov-west-1"},
		// A region no partition names takes its pattern's partition's hosts.
		{"DescribeVpcs", "eu-future-9", "https://ec2.eu-future-9.amazonaws.com ec2/eu-future-9"},
		// The old FIPS region form selects the plain region's host and signs as
		// given.
		{"DescribeVpcs", "fips-us-east-1", "https://ec2.us-east-1.amazonaws.com ec2/fips-us-east-1"},
		{"DescribeVpcs", "bad_region", "error: invalid input region bad_region"},
	} {
		if got := endpointTarget(t, specs, plain, c.operation, c.region); got != c.want {
			t.Errorf("%s in %s = %s, want %s", c.operation, c.region, got, c.want)
		}
	}
}

// environmentEngine builds an engine through the SDK's own configuration
// loader, so the settings arrive exactly as a client would read them.
func environmentEngine(t *testing.T) *Engine {
	t.Helper()
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg, testPartitions)
}

// assertEndpointsFromEnvironment checks FIPS, the region, attempts, and
// global and service endpoint URLs as the environment sets them, in turn.
func assertEndpointsFromEnvironment(t *testing.T, specs map[string]Spec) {
	t.Helper()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "none"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "none"))
	t.Setenv("AWS_REGION", "us-west-2")
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "true")
	t.Setenv("AWS_MAX_ATTEMPTS", "1")
	fips := environmentEngine(t)
	if got, want := endpointTarget(t, specs, fips, "DescribeVpcs", ""), "error: invalid input region "; got != want {
		t.Errorf("an empty region is the engine's own only through Lookup: got %s", got)
	}
	if got, want := endpointTarget(t, specs, fips, "DescribeVpcs", "us-west-2"), "https://ec2-fips.us-west-2.amazonaws.com ec2/us-west-2"; got != want {
		t.Errorf("FIPS: %s, want %s", got, want)
	}
	if fips.Region != "us-west-2" || fips.MaxAttempts != 1 {
		t.Errorf("region %q, attempts %d", fips.Region, fips.MaxAttempts)
	}
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "false")
	t.Setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:1/base")
	t.Setenv("AWS_ENDPOINT_URL_EC2", "http://127.0.0.1:2")
	assertConfiguredEndpointURLs(t, specs, environmentEngine(t))
	// FIPS with a configured URL is refused by EC2's rules, as here.
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "true")
	if got := endpointTarget(t, specs, environmentEngine(t), "DescribeVpcs", "us-west-2"); !strings.HasPrefix(got, "error: ") {
		t.Errorf("FIPS with a configured URL: %s", got)
	}
}

func assertConfiguredEndpointURLs(t *testing.T, specs map[string]Spec, custom *Engine) {
	t.Helper()
	if got, want := endpointTarget(t, specs, custom, "GetRole", "us-west-2"), "http://127.0.0.1:1/base iam/us-west-2"; got != want {
		t.Errorf("global endpoint URL: %s, want %s", got, want)
	}
	if got, want := endpointTarget(t, specs, custom, "DescribeVpcs", "us-west-2"), "http://127.0.0.1:2 ec2/us-west-2"; got != want {
		t.Errorf("service endpoint URL: %s, want %s", got, want)
	}
	request, err := buildRequest(context.Background(), specs["GetFunction"], &url.URL{Scheme: "http", Host: "127.0.0.1:1", Path: "/base"}, map[string]string{"FunctionName": "my-function"})
	if err != nil || request.URL.String() != "http://127.0.0.1:1/base/2015-03-31/functions/my-function" {
		t.Errorf("configured path is not joined: %v %v", request.URL, err)
	}
}

// A transport failure is retried, then UNKNOWN; a canceled context stops.
func TestTransportFailures(t *testing.T) {
	spec := loadSpecs(t)["GetRole"]
	engine := &Engine{
		Credentials: credentials.NewStaticCredentialsProvider("AKID", "s", ""), Sleep: func(context.Context, time.Duration) error { return nil },
		HTTPClient: doFunc(func(*http.Request) (*http.Response, error) { return nil, io.ErrUnexpectedEOF }),
	}
	if got, reason := engine.Lookup(context.Background(), spec, "us-east-1", "x"); got != Unknown || reason != "AWS transport or inspection failure" {
		t.Fatalf("got %s (%s)", got, reason)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, reason := engine.Lookup(ctx, spec, "us-east-1", "x"); got != Unknown || reason != "inspection canceled" {
		t.Fatalf("canceled: got %s (%s)", got, reason)
	}
}

type doFunc func(*http.Request) (*http.Response, error)

func (f doFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestCBORRoundTrip(t *testing.T) {
	encoded := encodeCBOR(map[string]any{"FleetIds": []string{"a", strings.Repeat("b", 300)}, "Name": "x"})
	decoded, err := decodeCBOR(encoded)
	fields, _ := decoded.(map[string]any)
	ids, _ := fields["FleetIds"].([]any)
	if err != nil || fields["Name"] != "x" || len(ids) != 2 || ids[1] != strings.Repeat("b", 300) {
		t.Fatalf("decoded %#v, %v", decoded, err)
	}
	for _, bad := range [][]byte{{0xbf, 0x63, 'a'}, {0x7a, 0xff, 0xff, 0xff, 0xff}, {0xa1}, {}} {
		if _, err := decodeCBOR(bad); err == nil {
			t.Errorf("% x decoded without error", bad)
		}
	}
	// As smithy's decoder, which the SDK uses: the first item counts.
	if value, err := decodeCBOR([]byte{0x61, 'a', 0x00}); err != nil || value != "a" {
		t.Errorf("trailing bytes: %#v, %v", value, err)
	}
}

// The engine answers every lookup from specs, so it must not depend on a
// single service client.
func TestNoServiceClients(t *testing.T) {
	output, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skip(err)
	}
	for _, dependency := range strings.Fields(string(output)) {
		if strings.HasPrefix(dependency, "github.com/aws/aws-sdk-go-v2/service/") {
			t.Errorf("awscall depends on %s", dependency)
		}
	}
}

var _ = aws.Config{}

// Recorded, redacted AWS responses must replay to the existence answer the
// engine reached live. Every testdata/recorded*.json file is replayed.
func TestRecordedResponsesReplay(t *testing.T) {
	order, lookups := loadRecordedLookups(t, recordedSpecs(t))
	conflicts := 0
	protocols := map[string]bool{}
	for _, id := range order {
		l := lookups[id]
		protocols[l.spec.Protocol] = true
		if strings.Contains(id, "conflict") {
			conflicts++
		}
		var slept []time.Duration
		client := &fakeClient{responses: l.queue}
		answer := testEngine(client, &slept).Inspect(context.Background(), l.spec, l.region, l.values)
		if answer.Result != l.expected || len(client.requests) != len(l.queue) {
			t.Errorf("%s: replay = %s (%s) after %d of %d responses, live = %s", id, answer.Result, answer.Reason, len(client.requests), len(l.queue), l.expected)
		}
	}
	if len(order) < 900 || conflicts < 200 || len(protocols) != 7 {
		t.Fatalf("%d recorded lookups replayed (%d conflict) across %d protocols", len(order), conflicts, len(protocols))
	}
	t.Logf("%d recorded lookups replayed, %d of them conflict lookups", len(order), conflicts)
}

// recordedSpecs indexes the shipped dependency and conflict specs the way
// recorded labels name them, and installs the dependency partitions.
func recordedSpecs(t *testing.T) map[string]Spec {
	t.Helper()
	load := func(name string) SpecSet {
		var set SpecSet
		data, err := packs.ReadFile("aws/lookup/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &set); err != nil {
			t.Fatal(err)
		}
		return set
	}
	dependency, conflict := load("specs-6.64.0.json"), load("conflict-specs-6.64.0.json")
	testPartitions = dependency.Partitions
	byKey := map[string]Spec{}
	for _, spec := range dependency.Specs {
		byKey[spec.Service+"/"+spec.Operation+"/"+spec.Field] = spec
	}
	for _, spec := range conflict.Specs {
		byKey["conflict "+spec.Service+"/"+spec.Operation] = spec
	}
	return byKey
}

// recordedLookup is one lookup's responses, in the order AWS sent them: a
// lookup that was retried live is replayed through the same retries.
type recordedLookup struct {
	spec     Spec
	region   string
	values   map[string]string
	expected Result
	queue    []recorded
}

type recordedResponse struct {
	Label    string            `json:"label"`
	Region   string            `json:"region"`
	ID       string            `json:"id"`
	Values   map[string]string `json:"values"`
	Status   int               `json:"status"`
	Headers  map[string]string `json:"headers"`
	Body     string            `json:"body"`
	Base64   string            `json:"body_base64"`
	Expected Result            `json:"expected"`
}

// loadRecordedLookups groups every testdata/recorded*.json response into
// lookups, in first-seen order.
func loadRecordedLookups(t *testing.T, byKey map[string]Spec) ([]string, map[string]*recordedLookup) {
	t.Helper()
	var order []string
	lookups := map[string]*recordedLookup{}
	names, err := filepath.Glob("testdata/recorded*.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		var file struct {
			Responses []recordedResponse `json:"responses"`
		}
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatal(err)
		}
		for _, r := range file.Responses {
			id, lookup, ok := recordedResponseLookup(t, name, byKey, r)
			if !ok {
				continue
			}
			if existing, seen := lookups[id]; seen {
				existing.queue = append(existing.queue, lookup.queue...)
				continue
			}
			lookups[id] = lookup
			order = append(order, id)
		}
	}
	return order, lookups
}

// recordedResponseLookup is the lookup one recorded response belongs to,
// holding just that response. ok is false for a response with no spec.
func recordedResponseLookup(t *testing.T, name string, byKey map[string]Spec, r recordedResponse) (string, *recordedLookup, bool) {
	t.Helper()
	parts := strings.Split(r.Label, "/")
	key := strings.Join(parts[:3], "/")
	if strings.Contains(name, "conflict") {
		key = "conflict " + strings.Join(parts[:2], "/")
	}
	spec, ok := byKey[key]
	if !ok {
		// Route 53 has hand-written SDK customizations, so the generator
		// refuses it: its lookups stay on SDK clients and have no spec.
		if !strings.HasPrefix(r.Label, "route53/") {
			t.Fatalf("%s: no spec", r.Label)
		}
		return "", nil, false
	}
	region := r.Region
	if region == "" {
		region = "us-east-1"
	}
	body := r.Body
	if r.Base64 != "" {
		raw, err := base64.StdEncoding.DecodeString(r.Base64)
		if err != nil {
			t.Fatal(err)
		}
		body = string(raw)
	}
	values := r.Values
	if values == nil {
		values = map[string]string{spec.Field: r.ID}
	}
	id := fmt.Sprint(name, " ", r.Label, " ", region, " ", values)
	return id, &recordedLookup{
		spec: spec, region: region, values: values, expected: Result(strings.ToUpper(string(r.Expected))),
		queue: []recorded{{Status: r.Status, Headers: r.Headers, Body: &body}},
	}, true
}
