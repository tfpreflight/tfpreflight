package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tfpreflight/tfpreflight/internal/packs"
	packdata "github.com/tfpreflight/tfpreflight/packs"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/tfpreflight/tfpreflight/internal/checks/dependencies"
	"golang.org/x/mod/modfile"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) Do(r *http.Request) (*http.Response, error) { return f(r) }

func testConfig(client transport) aws.Config {
	return aws.Config{
		Region: "us-east-1", HTTPClient: client,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "fake", SecretAccessKey: "fake"}, nil
		}), Retryer: func() aws.Retryer { return aws.NopRetryer{} },
	}
}

func compiledLookup(t *testing.T, key string) dependencies.Lookup {
	t.Helper()
	rules, err := Rules("6.64.0")
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		if lookupKey(rule.Lookup) == key {
			return rule.Lookup
		}
	}
	t.Fatalf("missing compiled lookup %s", key)
	return dependencies.Lookup{}
}

func TestTypedSDKLookups(t *testing.T) {
	const vpc = "vpc-0123456789abcdef0"
	for _, tc := range []struct {
		name, key, id, body, request string
		status                       int
		want                         dependencies.Existence
	}{
		{"list ID exists", "ec2/DescribeVpcs/VpcIds", vpc, `<DescribeVpcsResponse><vpcSet><item><vpcId>` + vpc + `</vpcId></item></vpcSet></DescribeVpcsResponse>`, "VpcId.1=" + vpc, 200, dependencies.Exists},
		{"provider not found", "ec2/DescribeVpcs/VpcIds", vpc, `<Response><Errors><Error><Code>InvalidVpcID.NotFound</Code><Message>missing</Message></Error></Errors></Response>`, "VpcId.1=" + vpc, 400, dependencies.NotFound},
		{"AccessDenied", "ec2/DescribeVpcs/VpcIds", vpc, `<Response><Errors><Error><Code>UnauthorizedOperation</Code><Message>denied</Message></Error></Errors></Response>`, "", 403, dependencies.Unknown},
		{"throttle", "ec2/DescribeVpcs/VpcIds", vpc, `<Response><Errors><Error><Code>RequestLimitExceeded</Code><Message>slow</Message></Error></Errors></Response>`, "", 400, dependencies.Unknown},
		{"unproven empty collection", "ec2/DescribeVpcs/VpcIds", vpc, `<DescribeVpcsResponse><vpcSet/></DescribeVpcsResponse>`, "", 200, dependencies.Unknown},
		{"wrong identifier", "ec2/DescribeVpcs/VpcIds", vpc, `<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-other</vpcId></item></vpcSet></DescribeVpcsResponse>`, "", 200, dependencies.Unknown},
		{"scalar ID exists", "dynamodb/DescribeTable/TableName", "example", `{"Table":{"TableName":"example"}}`, `"TableName":"example"`, 200, dependencies.Exists},
		{"modeled not found", "dynamodb/DescribeTable/TableName", "example", `{"__type":"com.amazonaws.dynamodb.v20120810#ResourceNotFoundException","message":"missing"}`, "", 400, dependencies.NotFound},
		{"generic bad request", "dynamodb/DescribeTable/TableName", "example", `{"__type":"ValidationException","message":"invalid"}`, "", 400, dependencies.Unknown},
		{"malformed response", "dynamodb/DescribeTable/TableName", "example", `not json`, "", 200, dependencies.Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			config := testConfig(func(r *http.Request) (*http.Response, error) {
				calls++
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(body), tc.request) {
					t.Fatalf("typed request = %s, want %s", body, tc.request)
				}
				return &http.Response{StatusCode: tc.status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})
			r := New("6.64.0", config)
			got, reason := r.Exists(context.Background(), compiledLookup(t, tc.key), dependencies.Scope{}, tc.id)
			if got != tc.want || calls != 1 {
				t.Fatalf("got %s (%s), calls=%d; want %s", got, reason, calls, tc.want)
			}
		})
	}
}

func TestRegistrySafetyAndDeduplication(t *testing.T) {
	l := compiledLookup(t, "ec2/DescribeVpcs/VpcIds")
	calls := 0
	config := testConfig(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("network unavailable") })
	r := New("6.64.0", config)
	var group sync.WaitGroup
	for i := 0; i < 10; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if got, _ := r.Exists(context.Background(), l, dependencies.Scope{}, "vpc-one"); got != dependencies.Unknown {
				t.Errorf("network error became %s", got)
			}
		}()
	}
	group.Wait()
	if calls != 1 {
		t.Fatalf("duplicate inspections: %d", calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, _ := r.Exists(ctx, l, dependencies.Scope{}, "vpc-two"); got != dependencies.Unknown {
		t.Fatal(got)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if got, _ := r.Exists(expired, l, dependencies.Scope{}, "vpc-two"); got != dependencies.Unknown {
		t.Fatal(got)
	}
	newer, err := packs.NewerThanCovered()
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := New(newer, config).Exists(context.Background(), l, dependencies.Scope{}, "vpc-two"); got != dependencies.Unknown {
		t.Fatal(got)
	}
	l.NotFoundCodes = []string{"UnauthorizedOperation"}
	if got, _ := r.Exists(context.Background(), l, dependencies.Scope{}, "vpc-two"); got != dependencies.Unknown {
		t.Fatal(got)
	}
	if calls != 1 {
		t.Fatalf("unsafe requests executed: %d", calls)
	}
	// Every tuple here has an adapter, so the unavailable path is exercised by
	// removing one: a rule whose lookup is not generated must answer unknown and
	// never reach AWS.
	unsupported := compiledLookup(t, "ec2/DescribeSubnets/SubnetIds")
	delete(r.lookups, lookupKey(unsupported))
	if got, reason := r.Exists(context.Background(), unsupported, dependencies.Scope{}, "subnet-one"); got != dependencies.Unknown || !strings.Contains(reason, "adapter unavailable") {
		t.Fatalf("missing adapter: %s %s", got, reason)
	}
	if calls != 1 {
		t.Fatal("unavailable adapter made a request")
	}
}

func TestGeneratedCorpusInvariants(t *testing.T) {
	rules, err := Rules("6.64.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1595 {
		t.Fatalf("compiler corpus changed: %d", len(rules))
	}
	assertEmbeddedRulesArePacks(t)
	report := readAdaptersReport(t)
	// What the runtime runs: the engine's lookups and the SDK's.
	built := New(ProviderVersion, aws.Config{})
	if built.unavailable != "" {
		t.Fatal(built.unavailable)
	}
	registry := built.lookups
	used := map[string]bool{}
	runnable := 0
	for _, rule := range rules {
		k := lookupKey(rule.Lookup)
		used[k] = true
		if registry[k] != nil {
			runnable++
		}
	}
	if runnable != report.Runtime {
		t.Fatalf("runtime count %d != %d", runnable, report.Runtime)
	}
	assertTuplesClassified(t, report, registry, used)
	assertSDKPins(t)
}

// assertEmbeddedRulesArePacks checks the embedded range pack is the one in
// packs/.
func assertEmbeddedRulesArePacks(t *testing.T) {
	t.Helper()
	original, err := os.ReadFile("../../../../packs/aws/dependency/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := packdata.AWS.ReadFile("aws/dependency/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, embedded) {
		t.Fatal("embedded pack differs from the compiled file in packs/")
	}
}

type adaptersReport struct {
	Tuples []struct {
		Lookup dependencies.Lookup `json:"lookup"`
		State  string              `json:"state"`
	} `json:"tuples"`
	Runtime int `json:"runtime_capable"`
}

func readAdaptersReport(t *testing.T) adaptersReport {
	t.Helper()
	var report adaptersReport
	data, err := os.ReadFile("testdata/adapters-report-6.64.0.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	return report
}

// assertTuplesClassified checks every lookup tuple is used, classified once,
// and has an adapter exactly when the report says it is generated, and that
// no adapter is orphaned.
func assertTuplesClassified(t *testing.T, report adaptersReport, registry map[string]lookupFunc, used map[string]bool) {
	t.Helper()
	if len(report.Tuples) != 264 || len(used) != 264 {
		t.Fatal("tuple corpus changed")
	}
	seen := map[string]bool{}
	for _, tuple := range report.Tuples {
		k := lookupKey(tuple.Lookup)
		if seen[k] || !used[k] || tuple.State == "" {
			t.Fatalf("duplicate, orphan or unclassified tuple %s", k)
		}
		seen[k] = true
		if (registry[k] != nil) != (tuple.State == "generated") {
			t.Fatalf("adapter/report mismatch %s", k)
		}
	}
	for k := range registry {
		if !used[k] {
			t.Fatalf("orphan %s", k)
		}
	}
}

// assertSDKPins checks go.mod selects every pinned SDK module at its pin,
// unreplaced, and the pin manifest agrees.
func assertSDKPins(t *testing.T) {
	t.Helper()
	var manifest struct {
		Services map[string]struct{ Module, Version string }
	}
	data, err := os.ReadFile("testdata/sdk-pins-6.64.0.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile("../../../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	mod, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		t.Fatal(err)
	}
	selected := map[string]string{}
	for _, r := range mod.Require {
		selected[r.Mod.Path] = r.Mod.Version
	}
	for module, version := range sdkVersions {
		if selected[module] != version {
			t.Fatalf("module %s version %s != pin %s", module, selected[module], version)
		}
		service := strings.TrimPrefix(module, "github.com/aws/aws-sdk-go-v2/service/")
		if manifest.Services[service].Version != version || manifest.Services[service].Module != module {
			t.Fatalf("manifest mismatch %s", module)
		}
		for _, r := range mod.Replace {
			if r.Old.Path == module {
				t.Fatalf("replaced exact SDK %s", module)
			}
		}
	}
}

// The generated families each need one proof through the real SDK: a result
// nested two levels down, a singular read that echoes no identifier, and an
// object that answers to either its name or its ARN.
func TestGeneratedSuccessFamilies(t *testing.T) {
	for _, tc := range []struct {
		name, key, id, body string
		status              int
		want                dependencies.Existence
	}{
		{
			"nested collection", "ec2/DescribeInstances/InstanceIds", "i-0123456789abcdef0",
			`<DescribeInstancesResponse><reservationSet><item><instancesSet><item><instanceId>i-0123456789abcdef0</instanceId></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`, 200, dependencies.Exists,
		},
		{
			"nested collection, other instance", "ec2/DescribeInstances/InstanceIds", "i-0123456789abcdef0",
			`<DescribeInstancesResponse><reservationSet><item><instancesSet><item><instanceId>i-999</instanceId></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`, 200, dependencies.Unknown,
		},
		{"singular read without an echo", "s3/HeadBucket/Bucket", "example-bucket", ``, 200, dependencies.Exists},
		{"modelled type differs from the wire code", "s3/HeadBucket/Bucket", "example-bucket", ``, 404, dependencies.NotFound},
		{
			"identity by ARN", "ecs/DescribeClusters/Clusters", "arn:aws:ecs:us-east-1:123456789012:cluster/app",
			`{"clusters":[{"clusterArn":"arn:aws:ecs:us-east-1:123456789012:cluster/app","clusterName":"app"}]}`, 200, dependencies.Exists,
		},
		{
			"identity by name", "ecs/DescribeClusters/Clusters", "app",
			`{"clusters":[{"clusterArn":"arn:aws:ecs:us-east-1:123456789012:cluster/app","clusterName":"app"}]}`, 200, dependencies.Exists,
		},
		{
			"reported as a failure, not returned", "ecs/DescribeClusters/Clusters", "app",
			`{"clusters":[],"failures":[{"arn":"app","reason":"MISSING"}]}`, 200, dependencies.Unknown,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := testConfig(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})
			got, reason := New("6.64.0", config).Exists(context.Background(), compiledLookup(t, tc.key), dependencies.Scope{}, tc.id)
			if got != tc.want {
				t.Fatalf("got %s (%s), want %s", got, reason, tc.want)
			}
		})
	}
}

// The same identifier in another region is another question, and gets its own
// inspection.
func TestScopeSeparatesOtherwiseIdenticalLookups(t *testing.T) {
	lookup := compiledLookup(t, "ec2/DescribeVpcs/VpcIds")
	var mu sync.Mutex
	regions := map[string]int{}
	config := testConfig(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		regions[strings.Split(r.URL.Host, ".")[1]]++
		mu.Unlock()
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
			`<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-one</vpcId></item></vpcSet></DescribeVpcsResponse>`))}, nil
	})
	registry := New("6.64.0", config)
	for _, scope := range []dependencies.Scope{
		{Account: "111111111111", Region: "us-east-1"},
		{Account: "111111111111", Region: "us-east-1"},
		{Account: "111111111111", Region: "eu-west-1"},
		{Account: "222222222222", Region: "us-east-1"},
	} {
		if got, reason := registry.Exists(context.Background(), lookup, scope, "vpc-one"); got != dependencies.Exists {
			t.Fatalf("%v: %s (%s)", scope, got, reason)
		}
	}
	if total := regions["us-east-1"] + regions["eu-west-1"]; total != 3 {
		t.Fatalf("inspections = %v, want one per scope and one cache hit", regions)
	}
	if regions["eu-west-1"] != 1 {
		t.Fatalf("the second region was not inspected in its own region: %v", regions)
	}
}

// Prefetch runs several inspections at once, but never more than the limit,
// and asks once per distinct question however many rules referenced it.
func TestPrefetchIsBoundedAndDeduplicated(t *testing.T) {
	const unique = 100
	var mu sync.Mutex
	var concurrent, peak, calls int
	config := testConfig(func(*http.Request) (*http.Response, error) {
		mu.Lock()
		calls++
		concurrent++
		if concurrent > peak {
			peak = concurrent
		}
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		concurrent--
		mu.Unlock()
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
			`<DescribeVpcsResponse><vpcSet/></DescribeVpcsResponse>`))}, nil
	})
	registry := New("6.64.0", config)
	lookup := compiledLookup(t, "ec2/DescribeVpcs/VpcIds")
	var requests []dependencies.LookupRequest
	for i := range unique {
		request := dependencies.LookupRequest{Lookup: lookup, Identifier: fmt.Sprintf("vpc-%03d", i)}
		requests = append(requests, request, request) // every identifier asked twice
	}
	registry.Prefetch(context.Background(), requests)
	if calls != unique {
		t.Fatalf("inspections = %d, want one per distinct identifier (%d)", calls, unique)
	}
	if peak > maxConcurrentLookups {
		t.Fatalf("peak concurrency %d exceeded the limit %d", peak, maxConcurrentLookups)
	}
	if peak < 2 {
		t.Fatalf("peak concurrency %d: prefetch ran sequentially", peak)
	}
	// Every answer is cached, so evaluation adds no inspections.
	for i := range unique {
		registry.Exists(context.Background(), lookup, dependencies.Scope{}, fmt.Sprintf("vpc-%03d", i))
	}
	if calls != unique {
		t.Fatalf("evaluation re-inspected: %d", calls)
	}
}

// Several callers arriving while one inspection is in flight share it.
func TestConcurrentCallersShareOneInspection(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	calls := 0
	config := testConfig(func(*http.Request) (*http.Response, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		<-release
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
			`<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-one</vpcId></item></vpcSet></DescribeVpcsResponse>`))}, nil
	})
	registry := New("6.64.0", config)
	lookup := compiledLookup(t, "ec2/DescribeVpcs/VpcIds")
	var group sync.WaitGroup
	answers := make([]dependencies.Existence, 16)
	for i := range answers {
		group.Add(1)
		go func() {
			defer group.Done()
			answers[i], _ = registry.Exists(context.Background(), lookup, dependencies.Scope{}, "vpc-one")
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	group.Wait()
	if calls != 1 {
		t.Fatalf("%d inspections for one identifier", calls)
	}
	for i, answer := range answers {
		if answer != dependencies.Exists {
			t.Fatalf("caller %d got %s", i, answer)
		}
	}
}

// A cancelled check stops scheduling, abandons what is in flight and leaves no
// goroutines behind.
func TestPrefetchStopsOnCancellation(t *testing.T) {
	before := runtime.NumGoroutine()
	started := make(chan struct{}, 512)
	config := testConfig(func(r *http.Request) (*http.Response, error) {
		started <- struct{}{}
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	registry := New("6.64.0", config)
	lookup := compiledLookup(t, "ec2/DescribeVpcs/VpcIds")
	var requests []dependencies.LookupRequest
	for i := range 200 {
		requests = append(requests, dependencies.LookupRequest{Lookup: lookup, Identifier: fmt.Sprintf("vpc-%03d", i)})
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { registry.Prefetch(ctx, requests); close(done) }()
	<-started
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("prefetch did not stop when the check was cancelled")
	}
	if got, _ := registry.Exists(ctx, lookup, dependencies.Scope{}, "vpc-001"); got != dependencies.Unknown {
		t.Fatalf("cancelled inspection answered %s", got)
	}
	for range 50 {
		if runtime.NumGoroutine() <= before+2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutines leaked: %d before, %d after", before, runtime.NumGoroutine())
}

// A service that never answers costs its own dependency a verdict, not the
// check, whether the inspection was asked for directly or gathered first.
func TestLookupTimeoutIsUnknown(t *testing.T) {
	restore := lookupTimeout
	lookupTimeout = 50 * time.Millisecond
	defer func() { lookupTimeout = restore }()

	config := testConfig(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	registry := New("6.64.0", config)
	lookup := compiledLookup(t, "ec2/DescribeVpcs/VpcIds")
	if got, reason := registry.Exists(context.Background(), lookup, dependencies.Scope{}, "vpc-one"); got != dependencies.Unknown {
		t.Fatalf("direct inspection: %s (%s)", got, reason)
	}
	started := time.Now()
	registry.Prefetch(context.Background(), []dependencies.LookupRequest{
		{Lookup: lookup, Identifier: "vpc-two"}, {Lookup: lookup, Identifier: "vpc-three"},
	})
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("gathered inspections ran without a timeout: %s", elapsed)
	}
	if got, _ := registry.Exists(context.Background(), lookup, dependencies.Scope{}, "vpc-two"); got != dependencies.Unknown {
		t.Fatalf("gathered inspection = %s", got)
	}
}

// Every enforcement claim must describe a dependency rule that exists with
// exactly those create semantics. An orphan claim is evidence about something
// the rules no longer hold, and must never block.
func TestEnforcementEvidenceMatchesTheCorpus(t *testing.T) {
	rules, err := Rules("6.64.0")
	if err != nil {
		t.Fatal(err)
	}
	present := map[string]bool{}
	for _, rule := range rules {
		present[rule.Fingerprint("6.64.0").Key()] = true
	}
	data, err := packs.ReadFile("aws/dependency/enforcement-6.64.0.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack dependencies.EnforcementPack
	if err := json.Unmarshal(data, &pack); err != nil {
		t.Fatal(err)
	}
	if len(pack.Claims) == 0 {
		t.Fatal("the enforcement pack is empty")
	}
	orphans := 0
	for _, claim := range pack.Claims {
		if !present[claim.Fingerprint.Key()] {
			orphans++
			t.Errorf("orphan evidence: %s.%s no longer has these create semantics (%s:%s %s)",
				claim.Fingerprint.Resource, claim.Fingerprint.Attribute,
				claim.Fingerprint.CreateService, claim.Fingerprint.CreateOperation, claim.Fingerprint.Member)
		}
	}
	if orphans == 0 {
		t.Logf("%d enforcement claims all match current rules", len(pack.Claims))
	}
	// The embedded copy must be the same evidence as the knowledge directory.
	embedded, problems := dependencies.EnforcementFor("6.64.0")
	if len(problems) != 0 {
		t.Errorf("embedded enforcement pack problems: %v", problems)
	}
	if embedded.Supported() == 0 {
		t.Error("the embedded pack supports no blocking fingerprints")
	}
}
