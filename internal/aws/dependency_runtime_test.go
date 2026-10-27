package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tfpreflight/tfpreflight/internal/checks/dependencies"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/tfpreflight/tfpreflight/internal/checks/dependencies/adapters"
	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

type dependencyHTTP func(*http.Request) (*http.Response, error)

func (f dependencyHTTP) Do(r *http.Request) (*http.Response, error) { return f(r) }

type dependencySpy struct{ calls int }

func (s *dependencySpy) Exists(context.Context, dependencies.Lookup, dependencies.Scope, string) (dependencies.Existence, string) {
	s.calls++
	return dependencies.Exists, "fake"
}

func dependencyDocument(t *testing.T) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(`{
	 "configuration":{"provider_config":{"aws":{"expressions":{"region":{"constant_value":"us-east-1"}}}},"root_module":{"resources":[{"address":"aws_subnet.test","mode":"managed","type":"aws_subnet","name":"test","provider_config_key":"aws","expressions":{"vpc_id":{"constant_value":"vpc-0123456789abcdef0"}}}]}},
	 "resource_changes":[{"address":"aws_subnet.test","mode":"managed","type":"aws_subnet","name":"test","change":{"actions":["create"],"after":{"vpc_id":"vpc-0123456789abcdef0"},"after_unknown":{}}}]
	}`), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func depBlock(doc map[string]any) map[string]any {
	return doc["configuration"].(map[string]any)["root_module"].(map[string]any)["resources"].([]any)[0].(map[string]any)
}

func depChange(doc map[string]any) map[string]any {
	return doc["resource_changes"].([]any)[0].(map[string]any)["change"].(map[string]any)
}

func depJSON(t *testing.T, doc map[string]any) []byte {
	t.Helper()
	b, e := json.Marshal(doc)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestDependencyRuntimeThroughTypedSDK(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		coverage   model.CheckStatus
		findings   int
		network    bool
		blocks     bool
	}{
		{"exists", `<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-0123456789abcdef0</vpcId></item></vpcSet></DescribeVpcsResponse>`, 200, model.CheckChecked, 0, false, false},
		{"missing", `<Response><Errors><Error><Code>InvalidVpcID.NotFound</Code></Error></Errors></Response>`, 400, model.CheckChecked, 1, false, true},
		{"denied", `<Response><Errors><Error><Code>UnauthorizedOperation</Code></Error></Errors></Response>`, 403, model.CheckPartialDependency, 0, false, false},
		{"throttled", `<Response><Errors><Error><Code>RequestLimitExceeded</Code></Error></Errors></Response>`, 400, model.CheckPartialDependency, 0, false, false},
		{"network", ``, 0, model.CheckPartialDependency, 0, true, false},
		{"empty", `<DescribeVpcsResponse/>`, 200, model.CheckPartialDependency, 0, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			cfg := typedVPCConfig(t, &calls, func() (*http.Response, error) {
				if tc.network {
					return nil, errors.New("offline")
				}
				return &http.Response{StatusCode: tc.status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})
			result := Result{Context: model.AWSContext{InspectionIdentity: "arn:aws:iam::123456789012:user/inspector", ApplyIdentity: "arn:aws:iam::999999999999:role/deployer"}, Coverage: model.Coverage{Resources: []model.ResourceCoverage{{Resource: "aws_subnet.test"}}}}
			applyDependencyRuntime(context.Background(), &result, depJSON(t, dependencyDocument(t)), "6.64.0", cfg)
			if calls != 1 || result.Coverage.Resources[0].Dependencies != tc.coverage || len(result.Findings) != tc.findings {
				t.Fatalf("calls=%d coverage=%s findings=%v debug=%v", calls, result.Coverage.Resources[0].Dependencies, result.Findings, result.Debug)
			}
			assertBlocksOnlyWhenMissing(t, result.Findings, tc.blocks)
		})
	}
}

// typedVPCConfig is an SDK config whose every request is counted, must go to
// the plan's region (us-east-1, not the SDK's us-west-2), and is answered by
// respond.
func typedVPCConfig(t *testing.T, calls *int, respond func() (*http.Response, error)) sdk.Config {
	t.Helper()
	return sdk.Config{Region: "us-west-2", Retryer: func() sdk.Retryer { return sdk.NopRetryer{} }, Credentials: sdk.CredentialsProviderFunc(func(context.Context) (sdk.Credentials, error) {
		return sdk.Credentials{AccessKeyID: "fake", SecretAccessKey: "fake"}, nil
	}), HTTPClient: dependencyHTTP(func(r *http.Request) (*http.Response, error) {
		*calls++
		if !strings.Contains(r.URL.Host, "us-east-1") {
			t.Errorf("ignored plan region: %s", r.URL.Host)
		}
		return respond()
	})}
}

// assertBlocksOnlyWhenMissing: aws_subnet.vpc_id carries verified create-time
// enforcement, so a missing VPC is a blocking finding. Anything short of a
// missing verdict must stay non-blocking.
func assertBlocksOnlyWhenMissing(t *testing.T, findings []model.Finding, missing bool) {
	t.Helper()
	for _, f := range findings {
		blocking := f.Severity == model.SeverityError && f.Confidence == model.ConfidenceHigh
		if missing {
			if !blocking {
				t.Fatalf("a verified missing reference did not block: %+v", f)
			}
			continue
		}
		if blocking {
			t.Fatalf("a rule without a missing verdict blocked: %+v", f)
		}
	}
}

func TestDependencyRuntimeGuardsBeforeInspection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{"unknown ID", func(d map[string]any) { depChange(d)["after_unknown"] = map[string]any{"vpc_id": true} }, dependencies.CoveragePartial},
		{"local expression", func(d map[string]any) {
			depBlock(d)["expressions"] = map[string]any{"vpc_id": map[string]any{"references": []string{"local.vpc"}}}
		}, dependencies.CoveragePartial},
		{"module expression", func(d map[string]any) {
			depBlock(d)["expressions"] = map[string]any{"vpc_id": map[string]any{"references": []string{"module.vpc.id"}}}
		}, dependencies.CoveragePartial},
		{"provider alias", func(d map[string]any) { depBlock(d)["provider_config_key"] = "aws.west" }, dependencies.CoveragePartial},
		{"missing configuration", func(d map[string]any) { delete(d, "configuration") }, dependencies.CoveragePartial},
		{"unset optional dependency", func(d map[string]any) { depBlock(d)["expressions"] = map[string]any{} }, dependencies.CoverageNoRule},
		{"unknown region", func(d map[string]any) { d["configuration"].(map[string]any)["provider_config"] = map[string]any{} }, dependencies.CoveragePartial},
		{"resource region override", func(d map[string]any) {
			depBlock(d)["expressions"].(map[string]any)["region"] = map[string]any{"constant_value": "us-west-2"}
		}, dependencies.CoveragePartial},
		{"same plan", addDependencyProducer, dependencies.CoverageChecked},
		{"replacement unknown", func(d map[string]any) {
			addDependencyProducer(d)
			d["resource_changes"].([]any)[1].(map[string]any)["change"].(map[string]any)["actions"] = []string{"delete", "create"}
		}, dependencies.CoveragePartial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := dependencyDocument(t)
			tc.mutate(doc)
			spy := &dependencySpy{}
			results, coverage, err := DependencyRuntime(context.Background(), depJSON(t, doc), "6.64.0", sdk.Config{}, "arn:aws:iam::123456789012:user/inspector", spy)
			if err != nil || spy.calls != 0 || coverage["aws_subnet.test"] != tc.want {
				t.Fatalf("err=%v calls=%d coverage=%v results=%v", err, spy.calls, coverage, results)
			}
			for _, r := range results {
				if r.Finding != nil {
					t.Fatalf("unexpected finding: %+v", r)
				}
			}
		})
	}
	newer, err := packs.NewerThanCovered()
	if err != nil {
		t.Fatal(err)
	}
	spy := &dependencySpy{}
	_, coverage, err := DependencyRuntime(context.Background(), depJSON(t, dependencyDocument(t)), newer, sdk.Config{}, "arn:aws:iam::123456789012:user/inspector", spy)
	if err != nil || spy.calls != 0 || coverage["aws_subnet.test"] != dependencies.CoverageUnsupported {
		t.Fatalf("version fallback: %v %v", err, coverage)
	}
}

func addDependencyProducer(d map[string]any) {
	depBlock(d)["expressions"] = map[string]any{"vpc_id": map[string]any{"references": []string{"aws_vpc.producer.id", "aws_vpc.producer"}}}
	depChange(d)["after"] = map[string]any{}
	depChange(d)["after_unknown"] = map[string]any{"vpc_id": true}
	d["resource_changes"] = append(d["resource_changes"].([]any), map[string]any{"address": "aws_vpc.producer", "mode": "managed", "type": "aws_vpc", "name": "producer", "change": map[string]any{"actions": []string{"create"}, "after": map[string]any{}, "after_unknown": map[string]any{"id": true}}})
}

// A rule whose typed lookup is unavailable is partial coverage, never a
// missing-dependency finding.
func TestDependencyRuntimeUnavailableAdapterIsPartial(t *testing.T) {
	doc := dependencyDocument(t)
	results, coverage, err := DependencyRuntime(context.Background(), depJSON(t, doc), "6.64.0", sdk.Config{},
		"arn:aws:iam::123456789012:user/inspector", unavailableResolver{})
	if err != nil || coverage["aws_subnet.test"] != dependencies.CoveragePartial {
		t.Fatalf("err=%v coverage=%v results=%v", err, coverage, results)
	}
	for _, r := range results {
		if r.Finding != nil {
			t.Fatalf("unavailable adapter became a violation: %+v", r)
		}
	}
}

type unavailableResolver struct{}

func (unavailableResolver) Exists(context.Context, dependencies.Lookup, dependencies.Scope, string) (dependencies.Existence, string) {
	return dependencies.Unknown, "typed lookup adapter unavailable: ec2/DescribeVpcs/VpcIds"
}

func TestDependencyModuleGraphPreserved(t *testing.T) {
	for _, variable := range []bool{false, true} {
		doc := dependencyDocument(t)
		block := depBlock(doc)
		if variable {
			block["expressions"] = map[string]any{"vpc_id": map[string]any{"references": []string{"var.vpc_id"}}}
		}
		root := doc["configuration"].(map[string]any)["root_module"].(map[string]any)
		delete(root, "resources")
		root["module_calls"] = map[string]any{"child": map[string]any{"module": map[string]any{"resources": []any{block}}}}
		change := doc["resource_changes"].([]any)[0].(map[string]any)
		change["address"] = "module.child.aws_subnet.test"
		change["module_address"] = "module.child"
		spy := &dependencySpy{}
		_, coverage, err := DependencyRuntime(context.Background(), depJSON(t, doc), "6.64.0", sdk.Config{}, "arn:aws:iam::123456789012:user/inspector", spy)
		want, calls := dependencies.CoverageChecked, 1
		if variable {
			want, calls = dependencies.CoveragePartial, 0
		}
		if err != nil || spy.calls != calls || coverage[change["address"].(string)] != want {
			t.Fatalf("module variable=%v err=%v calls=%d coverage=%v", variable, err, spy.calls, coverage)
		}
	}
}

func TestDependencyScopeDoesNotBorrowAnotherAccount(t *testing.T) {
	for _, id := range []string{"arn:aws:ec2:us-east-1:999999999999:vpc/vpc-other", "arn:aws:ec2:us-west-2:123456789012:vpc/vpc-other", "arn:aws-cn:iam::123456789012:role/other"} {
		spy := &dependencySpy{}
		r := dependencyScopeResolver{next: spy, account: "123456789012", region: "us-east-1", partition: "aws"}
		got, reason := r.Exists(context.Background(), dependencies.Lookup{}, dependencies.Scope{}, id)
		if got != dependencies.Unknown || spy.calls != 0 || reason == "" {
			t.Fatalf("scope leaked: %s %s calls=%d", got, reason, spy.calls)
		}
	}
}

// Ten resources referencing one VPC ask AWS once. The answer is a property of
// the identifier, not of the resource that referenced it.
func TestDependencyRuntimeAsksOncePerIdentifier(t *testing.T) {
	doc := dependencyDocument(t)
	block := depBlock(doc)
	change := doc["resource_changes"].([]any)[0].(map[string]any)
	resources := []any{block}
	changes := []any{change}
	for i := 1; i < 10; i++ {
		address := fmt.Sprintf("aws_subnet.test%d", i)
		copyBlock := map[string]any{
			"address": address, "mode": "managed", "type": "aws_subnet", "name": fmt.Sprintf("test%d", i),
			"provider_config_key": "aws", "expressions": map[string]any{"vpc_id": map[string]any{"constant_value": "vpc-0123456789abcdef0"}},
		}
		copyChange := map[string]any{
			"address": address, "mode": "managed", "type": "aws_subnet", "name": fmt.Sprintf("test%d", i),
			"change": map[string]any{"actions": []string{"create"}, "after": map[string]any{"vpc_id": "vpc-0123456789abcdef0"}, "after_unknown": map[string]any{}},
		}
		resources = append(resources, copyBlock)
		changes = append(changes, copyChange)
	}
	doc["configuration"].(map[string]any)["root_module"].(map[string]any)["resources"] = resources
	doc["resource_changes"] = changes

	calls := 0
	config := sdk.Config{
		Region: "us-east-1", Retryer: func() sdk.Retryer { return sdk.NopRetryer{} },
		Credentials: sdk.CredentialsProviderFunc(func(context.Context) (sdk.Credentials, error) {
			return sdk.Credentials{AccessKeyID: "fake", SecretAccessKey: "fake"}, nil
		}),
		HTTPClient: dependencyHTTP(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
				`<DescribeVpcsResponse><vpcSet><item><vpcId>vpc-0123456789abcdef0</vpcId></item></vpcSet></DescribeVpcsResponse>`))}, nil
		}),
	}
	_, coverage, err := DependencyRuntime(context.Background(), depJSON(t, doc), "6.64.0", config,
		"arn:aws:iam::123456789012:user/inspector", nil)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("one identifier inspected %d times", calls)
	}
	for address, state := range coverage {
		if state != dependencies.CoverageChecked {
			t.Fatalf("%s = %s", address, state)
		}
	}
	if len(coverage) != 10 {
		t.Fatalf("coverage = %d resources", len(coverage))
	}
}

// sequentialOnly hides Prefetch, so the same registry can be measured the way
// the runtime behaved before lookups were gathered.
type sequentialOnly struct {
	next dependencies.ExistenceResolver
}

func (s sequentialOnly) Exists(ctx context.Context, l dependencies.Lookup, scope dependencies.Scope, id string) (dependencies.Existence, string) {
	return s.next.Exists(ctx, l, scope, id)
}

// dependencyScalePlan builds a plan of subnets referencing external VPCs, one
// per subnet except every fifth, which repeats the first: a real plan reuses a
// handful of shared parents.
func dependencyScalePlan(t *testing.T, checks int) ([]byte, int) {
	t.Helper()
	doc := dependencyDocument(t)
	var resources, changes []any
	unique := map[string]bool{}
	for i := range checks {
		address := fmt.Sprintf("aws_subnet.test%d", i)
		vpc := fmt.Sprintf("vpc-%017d", i)
		if i%5 == 4 {
			vpc = "vpc-00000000000000000"
		}
		unique[vpc] = true
		resources = append(resources, map[string]any{
			"address": address, "mode": "managed", "type": "aws_subnet",
			"name": fmt.Sprintf("test%d", i), "provider_config_key": "aws",
			"expressions": map[string]any{"vpc_id": map[string]any{"constant_value": vpc}},
		})
		changes = append(changes, map[string]any{
			"address": address, "mode": "managed", "type": "aws_subnet",
			"name": fmt.Sprintf("test%d", i), "change": map[string]any{
				"actions": []string{"create"},
				"after":   map[string]any{"vpc_id": vpc}, "after_unknown": map[string]any{},
			},
		})
	}
	doc["configuration"].(map[string]any)["root_module"].(map[string]any)["resources"] = resources
	doc["resource_changes"] = changes
	return depJSON(t, doc), len(unique)
}

// Dependency inspection scales by asking once per distinct identifier and by
// asking several at a time, without exceeding the limit.
func TestDependencyRuntimeScales(t *testing.T) {
	const latency = 10 * time.Millisecond
	for _, checks := range []int{250, 500, 1000, 1500} {
		plan, unique := dependencyScalePlan(t, checks)
		modes := []string{"bounded"}
		if checks <= 250 {
			modes = append([]string{"sequential"}, modes...)
		}
		for _, mode := range modes {
			vpcs := &scaleFakeVPCs{latency: latency}
			config := vpcs.config()
			var resolver dependencies.ExistenceResolver
			if mode == "sequential" {
				resolver = sequentialOnly{adapters.New("6.64.0", config)}
			}
			started := time.Now()
			_, coverage, err := DependencyRuntime(context.Background(), plan, "6.64.0", config,
				"arn:aws:iam::123456789012:user/inspector", resolver)
			elapsed := time.Since(started)
			if err != nil {
				t.Fatal(err)
			}
			assertScaleRun(t, checks, unique, mode, vpcs, coverage)
			t.Logf("checks=%3d unique=%3d mode=%-10s calls=%3d duplicates-avoided=%3d peak-concurrency=%d elapsed=%s",
				checks, unique, mode, vpcs.calls, checks-unique, vpcs.peak, elapsed.Round(time.Millisecond))
		}
	}
}

// scaleFakeVPCs answers every DescribeVpcs with the VPC asked for, after
// latency, and counts calls and peak concurrency.
type scaleFakeVPCs struct {
	latency                 time.Duration
	mu                      sync.Mutex
	calls, concurrent, peak int
}

func (f *scaleFakeVPCs) config() sdk.Config {
	return sdk.Config{
		Region: "us-east-1", Retryer: func() sdk.Retryer { return sdk.NopRetryer{} },
		Credentials: sdk.CredentialsProviderFunc(func(context.Context) (sdk.Credentials, error) {
			return sdk.Credentials{AccessKeyID: "fake", SecretAccessKey: "fake"}, nil
		}),
		HTTPClient: dependencyHTTP(f.describeVpcs),
	}
}

func (f *scaleFakeVPCs) describeVpcs(r *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(r.Body)
	identifier := ""
	if parts := strings.SplitN(string(body), "VpcId.1=", 2); len(parts) == 2 {
		identifier = strings.SplitN(parts[1], "&", 2)[0]
	}
	f.mu.Lock()
	f.calls++
	f.concurrent++
	if f.concurrent > f.peak {
		f.peak = f.concurrent
	}
	f.mu.Unlock()
	time.Sleep(f.latency)
	f.mu.Lock()
	f.concurrent--
	f.mu.Unlock()
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
		`<DescribeVpcsResponse><vpcSet><item><vpcId>` + identifier + `</vpcId></item></vpcSet></DescribeVpcsResponse>`))}, nil
}

// assertScaleRun checks every resource was checked, each distinct
// identifier was inspected once, and bounded lookups overlapped within the
// limit.
func assertScaleRun(t *testing.T, checks, unique int, mode string, vpcs *scaleFakeVPCs, coverage map[string]string) {
	t.Helper()
	for address, state := range coverage {
		if state != dependencies.CoverageChecked {
			t.Fatalf("%s = %s", address, state)
		}
	}
	if vpcs.calls != unique {
		t.Fatalf("%d checks, %s: %d inspections for %d distinct identifiers", checks, mode, vpcs.calls, unique)
	}
	if mode != "bounded" {
		return
	}
	if vpcs.peak > 8 {
		t.Fatalf("peak concurrency %d exceeded the limit", vpcs.peak)
	}
	if checks >= 50 && vpcs.peak < 2 {
		t.Fatalf("peak concurrency %d: lookups did not overlap", vpcs.peak)
	}
}

// A cancelled check stops inspecting and reports partial coverage rather than
// failing the tool.
func TestDependencyRuntimeHonoursCancellation(t *testing.T) {
	before := runtime.NumGoroutine()
	plan, _ := dependencyScalePlan(t, 50)
	config := sdk.Config{
		Region: "us-east-1", Retryer: func() sdk.Retryer { return sdk.NopRetryer{} },
		Credentials: sdk.CredentialsProviderFunc(func(context.Context) (sdk.Credentials, error) {
			return sdk.Credentials{AccessKeyID: "fake", SecretAccessKey: "fake"}, nil
		}),
		HTTPClient: dependencyHTTP(func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			return nil, r.Context().Err()
		}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	results, coverage, err := DependencyRuntime(ctx, plan, "6.64.0", config, "arn:aws:iam::123456789012:user/inspector", nil)
	if err != nil {
		t.Fatal(err)
	}
	for address, state := range coverage {
		if state != dependencies.CoveragePartial {
			t.Fatalf("%s = %s after cancellation", address, state)
		}
	}
	for _, result := range results {
		if result.Finding != nil {
			t.Fatalf("cancellation became a finding: %+v", result)
		}
	}
	for range 50 {
		if runtime.NumGoroutine() <= before+2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutines leaked: %d before, %d after", before, runtime.NumGoroutine())
}

// Gathering lookups must not turn a same-plan reference into an inspection:
// with the real registry behind it, a plan that creates its own parent reaches
// AWS not at all.
func TestGatheredLookupsSkipSamePlanTargets(t *testing.T) {
	doc := dependencyDocument(t)
	addDependencyProducer(doc)
	config := sdk.Config{
		Region: "us-east-1", Retryer: func() sdk.Retryer { return sdk.NopRetryer{} },
		Credentials: sdk.CredentialsProviderFunc(func(context.Context) (sdk.Credentials, error) {
			return sdk.Credentials{AccessKeyID: "fake", SecretAccessKey: "fake"}, nil
		}),
		HTTPClient: dependencyHTTP(func(r *http.Request) (*http.Response, error) {
			t.Errorf("inspected AWS for a target this plan creates: %s", r.URL)
			return nil, errors.New("must not inspect")
		}),
	}
	results, coverage, err := DependencyRuntime(context.Background(), depJSON(t, doc), "6.64.0", config,
		"arn:aws:iam::123456789012:user/inspector", nil)
	if err != nil {
		t.Fatal(err)
	}
	if coverage["aws_subnet.test"] != dependencies.CoverageChecked {
		t.Fatalf("coverage = %v", coverage)
	}
	satisfied := false
	for _, result := range results {
		if result.Address != "aws_subnet.test" {
			continue
		}
		switch {
		case result.Verdict == dependencies.VerdictSatisfiedByPlan:
			satisfied = true
		case result.Verdict != dependencies.VerdictNotApplicable:
			t.Fatalf("result = %+v", result)
		}
	}
	if !satisfied {
		t.Fatal("the same-plan reference was not recognised")
	}
}

// Answers gathered together stay independent: one denied inspection does not
// change what the others concluded.
func TestGatheredLookupsKeepVerdictsIndependent(t *testing.T) {
	doc := dependencyDocument(t)
	var resources, changes []any
	targets := map[string]string{"present": "vpc-00000000000000001", "absent": "vpc-00000000000000002", "denied": "vpc-00000000000000003"}
	for name, vpc := range targets {
		address := "aws_subnet." + name
		resources = append(resources, map[string]any{
			"address": address, "mode": "managed", "type": "aws_subnet", "name": name,
			"provider_config_key": "aws", "expressions": map[string]any{"vpc_id": map[string]any{"constant_value": vpc}},
		})
		changes = append(changes, map[string]any{
			"address": address, "mode": "managed", "type": "aws_subnet", "name": name,
			"change": map[string]any{"actions": []string{"create"}, "after": map[string]any{"vpc_id": vpc}, "after_unknown": map[string]any{}},
		})
	}
	doc["configuration"].(map[string]any)["root_module"].(map[string]any)["resources"] = resources
	doc["resource_changes"] = changes

	config := sdk.Config{
		Region: "us-east-1", Retryer: func() sdk.Retryer { return sdk.NopRetryer{} },
		Credentials: sdk.CredentialsProviderFunc(func(context.Context) (sdk.Credentials, error) {
			return sdk.Credentials{AccessKeyID: "fake", SecretAccessKey: "fake"}, nil
		}),
		HTTPClient: dependencyHTTP(func(r *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(r.Body)
			switch {
			case strings.Contains(string(body), targets["absent"]):
				return &http.Response{StatusCode: 400, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
					`<Response><Errors><Error><Code>InvalidVpcID.NotFound</Code></Error></Errors></Response>`))}, nil
			case strings.Contains(string(body), targets["denied"]):
				return &http.Response{StatusCode: 403, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
					`<Response><Errors><Error><Code>UnauthorizedOperation</Code></Error></Errors></Response>`))}, nil
			}
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
				`<DescribeVpcsResponse><vpcSet><item><vpcId>` + targets["present"] + `</vpcId></item></vpcSet></DescribeVpcsResponse>`))}, nil
		}),
	}
	results, coverage, err := DependencyRuntime(context.Background(), depJSON(t, doc), "6.64.0", config,
		"arn:aws:iam::123456789012:user/inspector", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"aws_subnet.present": dependencies.CoverageChecked,
		"aws_subnet.absent":  dependencies.CoverageChecked,
		"aws_subnet.denied":  dependencies.CoveragePartial,
	}
	for address, state := range want {
		if coverage[address] != state {
			t.Fatalf("%s = %s, want %s", address, coverage[address], state)
		}
	}
	findings := map[string]int{}
	for _, result := range results {
		if result.Finding != nil {
			findings[result.Address]++
		}
	}
	if len(findings) != 1 || findings["aws_subnet.absent"] != 1 {
		t.Fatalf("findings = %v, want only the absent target reported", findings)
	}
}

// A real plan with nested blocks, through the real registry and the typed SDK:
// produced values are never inspected, external ones are, and a missing
// external target is reported.
func TestDependencyRuntimeNestedThroughTypedSDK(t *testing.T) {
	plan, err := os.ReadFile(filepath.Join("..", "checks", "dependencies", "testdata", "nested-references.json"))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	asked := map[string]int{}
	config := sdk.Config{
		Region: "us-east-1", Retryer: func() sdk.Retryer { return sdk.NopRetryer{} },
		Credentials: sdk.CredentialsProviderFunc(func(context.Context) (sdk.Credentials, error) {
			return sdk.Credentials{AccessKeyID: "fake", SecretAccessKey: "fake"}, nil
		}),
		HTTPClient: dependencyHTTP(func(r *http.Request) (*http.Response, error) {
			body, _ := io.ReadAll(r.Body)
			text := string(body)
			mu.Lock()
			switch {
			case strings.Contains(text, "subnet-0aaaaaaaaaaaaaaaa"):
				asked["subnet-external"]++
			case strings.Contains(text, "sg-0ccccccccccccccc0"), strings.Contains(text, "sg-0ddddddddddddddd0"):
				asked["security-group"]++
			case strings.Contains(text, "RoleName=probe"), strings.Contains(r.URL.Path, "probe"):
				// The role each function names by ARN is a dependency of its
				// own; the name is read out of the ARN.
				asked["iam-role"]++
			default:
				asked["unexpected:"+text]++
			}
			mu.Unlock()
			if strings.Contains(text, "subnet-0aaaaaaaaaaaaaaaa") {
				return &http.Response{StatusCode: 400, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
					`<Response><Errors><Error><Code>InvalidSubnetID.NotFound</Code></Error></Errors></Response>`))}, nil
			}
			if strings.Contains(text, "RoleName=probe") {
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
					`<GetRoleResponse><GetRoleResult><Role><RoleName>probe</RoleName></Role></GetRoleResult></GetRoleResponse>`))}, nil
			}
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
				`<DescribeSecurityGroupsResponse><securityGroupInfo><item><groupId>sg-0ccccccccccccccc0</groupId></item></securityGroupInfo></DescribeSecurityGroupsResponse>`))}, nil
		}),
	}
	results, coverage, err := DependencyRuntime(context.Background(), plan, "6.64.0", config,
		"arn:aws:iam::123456789012:user/inspector", nil)
	if err != nil {
		t.Fatal(err)
	}
	for key := range asked {
		if strings.HasPrefix(key, "unexpected") {
			t.Fatalf("inspected something the plan produces: %s", key)
		}
	}
	findings := map[string]int{}
	for _, result := range results {
		if result.Finding != nil {
			findings[result.Address]++
		}
		if result.Address == "aws_lambda_function.same_plan" && result.Finding != nil {
			t.Fatalf("a nested target this plan creates was reported: %+v", result)
		}
	}
	if findings["aws_lambda_function.external"] != 1 {
		t.Fatalf("findings = %v, want the missing external subnet reported", findings)
	}
	if coverage["aws_lambda_function.same_plan"] != dependencies.CoveragePartial {
		t.Fatalf("same-plan nested coverage = %s", coverage["aws_lambda_function.same_plan"])
	}
	if asked["subnet-external"] != 1 {
		t.Fatalf("external subnet inspected %d times", asked["subnet-external"])
	}
}

// Evaluation classifies twice: once to gather the questions, once to read the
// answers. This measures that plan-side cost alone, with no inspection at all.
func TestDependencyGatheringCost(t *testing.T) {
	for _, checks := range []int{250, 1500} {
		plan, unique := dependencyScalePlan(t, checks)
		spy := &dependencySpy{}
		started := time.Now()
		_, coverage, err := DependencyRuntime(context.Background(), plan, "6.64.0", sdk.Config{},
			"arn:aws:iam::123456789012:user/inspector", spy)
		elapsed := time.Since(started)
		if err != nil {
			t.Fatal(err)
		}
		if len(coverage) != checks {
			t.Fatalf("coverage = %d resources, want %d", len(coverage), checks)
		}
		t.Logf("checks=%4d unique=%4d plan-side elapsed=%s (no inspection)", checks, unique, elapsed.Round(time.Millisecond))
	}
}

// A claim in the shipped enforcement evidence that did not load is reported in
// the run's diagnostics, shown with --debug, not printed on its own.
func TestEvidenceProblemsReachDiagnostics(t *testing.T) {
	checked := Result{}
	applyDependencyResults(&checked, dependencyOutcome{EvidenceProblems: []string{"dependency enforcement evidence for 6.64.0: claim x: conflicting statuses"}}, nil)
	if len(checked.Debug) != 1 || checked.Debug[0] != "dependency enforcement evidence for 6.64.0: claim x: conflicting statuses" {
		t.Fatalf("debug = %q", checked.Debug)
	}
	if len(checked.Findings) != 0 {
		t.Fatalf("an evidence problem became a finding: %+v", checked.Findings)
	}
}
