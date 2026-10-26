package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/tfpreflight/tfpreflight/internal/aws"
	"github.com/tfpreflight/tfpreflight/internal/check"
	"github.com/tfpreflight/tfpreflight/internal/checks/dependencies"
	"github.com/tfpreflight/tfpreflight/internal/plan"
	"github.com/tfpreflight/tfpreflight/internal/report"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

type releaseInspector struct {
	state dependencies.Existence
	calls int
}

func (r *releaseInspector) Exists(ctx context.Context, _ dependencies.Lookup, _ dependencies.Scope, _ string) (dependencies.Existence, string) {
	r.calls++
	if ctx.Err() != nil {
		return dependencies.Unknown, "inspection canceled"
	}
	return r.state, "inspection credentials unavailable"
}

// An actual process boundary, using the test executable with a command-local
// fake environment. Production has no environment variable or flag to enable it.
func TestReleaseCLIProcess(_ *testing.T) {
	scenario := os.Getenv("TFPREFLIGHT_RELEASE_PROCESS")
	if scenario == "" {
		return
	}
	services := check.Production()
	services.Detect = func(context.Context, []plan.ToolKind) (plan.Tool, error) {
		return plan.Tool{Name: "Terraform", Version: "1.12.0"}, nil
	}
	services.Configuration = func(string) (bool, error) { return true, nil }
	services.Show = releaseShow(scenario)
	services.AWS = releaseAWS(scenario)
	args := os.Args
	for i, arg := range args {
		if arg == "--" {
			args = args[i+1:]
			break
		}
	}
	if scenario == "signals" {
		// Terraform itself, as found on PATH, and main's signal handling.
		services = check.Production()
		services.Configuration = func(string) (bool, error) { return true, nil }
		os.Exit(runWithSignals(rootWithServices(services), args, os.Stdout, os.Stderr))
	}
	os.Exit(runRoot(context.Background(), rootWithServices(services), args, os.Stdout, os.Stderr))
}

// releaseShow is terraform show for a scenario: the project's plan.json
// unless the scenario breaks it.
func releaseShow(scenario string) func(context.Context, plan.Tool, string) ([]byte, error) {
	return func(context.Context, plan.Tool, string) ([]byte, error) {
		switch scenario {
		case "show-error":
			return nil, errors.New("terraform show failed")
		case "malformed":
			return []byte(`not JSON`), nil
		case "invalid-envelope":
			return []byte(`{}`), nil
		}
		return os.ReadFile("plan.json")
	}
}

// releaseFindings are the synthetic AWS findings a scenario injects.
var releaseFindings = map[string][]model.Finding{
	"blocking":       {releaseBlockingFinding},
	"newer-blocking": {releaseBlockingFinding},
	"older":          {releaseBlockingFinding},
	"warning":        {{ID: "synthetic", Resource: "aws_subnet.test", Category: "test", Severity: model.SeverityWarning, Confidence: model.ConfidenceMedium, Title: "Synthetic non-blocking fixture"}},
}

var releaseBlockingFinding = model.Finding{ID: "synthetic", Resource: "aws_subnet.test", Category: "test", Severity: model.SeverityError, Confidence: model.ConfidenceHigh, Title: "Synthetic blocking fixture"}

// releaseAWS is the AWS check for a scenario. Dependencies run through the
// real dependency runtime against a fake inspector.
func releaseAWS(scenario string) func(context.Context, []model.PlannedChange, string, string, []byte) (aws.Result, error) {
	return func(ctx context.Context, changes []model.PlannedChange, _, version string, data []byte) (aws.Result, error) {
		switch scenario {
		case "missing-version", "multiple-versions":
			return aws.Result{}, errors.New("BUG: AWS executed without a provider version")
		case "engine-error":
			return aws.Result{}, errors.New("cannot initialize inspection engine")
		}
		result := aws.Result{Debug: []string{"z debug", "a debug"}, Findings: append([]model.Finding(nil), releaseFindings[scenario]...)}
		inspector := &releaseInspector{state: releaseDependencyState(scenario)}
		if scenario == "cancel-inspection" {
			c, cancel := context.WithCancel(ctx)
			cancel()
			ctx = c
		}
		results, coverage, err := aws.DependencyRuntime(ctx, data, version, sdk.Config{}, "arn:aws:iam::123456789012:user/inspector", inspector)
		if err != nil {
			return result, err
		}
		if scenario == "same-plan" && inspector.calls != 0 {
			return result, fmt.Errorf("same-plan inspection calls: %d", inspector.calls)
		}
		addReleaseDependencies(&result, results, coverage, changes)
		return result, nil
	}
}

// releaseDependencyState is what the fake inspector says about every target.
func releaseDependencyState(scenario string) dependencies.Existence {
	switch scenario {
	case "partial", "cancel-inspection":
		return dependencies.Unknown
	case "dependency-blocking":
		// A real dependency rule, not a synthetic finding: aws_subnet.vpc_id
		// carries verified create-time enforcement, so an absent VPC has to
		// travel through the engine's blocking gate and out as exit 1.
		return dependencies.NotFound
	}
	return dependencies.Exists
}

// addReleaseDependencies adds the dependency findings, debug lines and
// coverage to the result.
func addReleaseDependencies(result *aws.Result, results []dependencies.Result, coverage map[string]string, changes []model.PlannedChange) {
	for _, r := range results {
		if r.Finding != nil {
			result.Findings = append(result.Findings, *r.Finding)
		}
		result.Debug = append(result.Debug, r.Address+": dependency "+r.Verdict+": "+r.Reason)
	}
	for _, c := range changes {
		status := model.CheckNoDependencyRule
		switch coverage[c.Address] {
		case dependencies.CoverageChecked:
			status = model.CheckChecked
		case dependencies.CoveragePartial:
			status = model.CheckPartialDependency
		}
		result.Coverage.Resources = append(result.Coverage.Resources, model.ResourceCoverage{Resource: c.Address, Trust: "generated", Permissions: model.CheckNotApplicable, Conflicts: model.CheckNotApplicable, Quota: model.CheckNotApplicable, Dependencies: status})
	}
}

const releasePlan = `{"format_version":"1.2","planned_values":{},"configuration":{"provider_config":{"aws":{"full_name":"registry.terraform.io/hashicorp/aws","expressions":{"region":{"constant_value":"us-east-1"}}}},"root_module":{"resources":[{"mode":"managed","type":"aws_subnet","name":"test","provider_config_key":"aws","expressions":{"vpc_id":{"constant_value":"vpc-0123456789abcdef0"}}}]}},"resource_changes":[{"address":"aws_subnet.test","mode":"managed","type":"aws_subnet","name":"test","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"after":{"vpc_id":"vpc-0123456789abcdef0"},"after_unknown":{}}}],"errored":false}`

func cliProject(t *testing.T, scenario string) string {
	t.Helper()
	dir := t.TempDir()
	lock := "provider \"registry.terraform.io/hashicorp/aws\" {\n version = \"6.64.0\"\n}\n"
	switch scenario {
	case "newer", "newer-blocking":
		lock = strings.ReplaceAll(lock, "6.64.0", "9.0.0")
	case "older":
		lock = strings.ReplaceAll(lock, "6.64.0", "5.50.0")
	case "config":
		lock = strings.ReplaceAll(lock, "6.64.0", "9.0.0")
		if err := os.WriteFile(filepath.Join(dir, ".tfpreflight.yml"), []byte("provider_version: 6.64.0\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if scenario == "multiple-versions" {
		lock += lock
	}
	if scenario != "missing-version" {
		if err := os.WriteFile(filepath.Join(dir, ".terraform.lock.hcl"), []byte(lock), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	plan := []byte(releasePlan)
	if scenario == "same-plan" {
		var doc map[string]any
		if err := json.Unmarshal(plan, &doc); err != nil {
			t.Fatal(err)
		}
		root := doc["configuration"].(map[string]any)["root_module"].(map[string]any)
		root["resources"].([]any)[0].(map[string]any)["expressions"] = map[string]any{"vpc_id": map[string]any{"references": []string{"aws_vpc.main.id", "aws_vpc.main"}}}
		changes := doc["resource_changes"].([]any)
		changes[0].(map[string]any)["change"] = map[string]any{"actions": []string{"create"}, "after": map[string]any{}, "after_unknown": map[string]any{"vpc_id": true}}
		doc["resource_changes"] = append(changes, map[string]any{"address": "aws_vpc.main", "mode": "managed", "type": "aws_vpc", "name": "main", "provider_name": "registry.terraform.io/hashicorp/aws", "change": map[string]any{"actions": []string{"create"}, "after": map[string]any{}, "after_unknown": map[string]any{"id": true}}})
		var err error
		plan, err = json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range map[string][]byte{"tfplan": []byte("opaque plan"), "plan.json": plan} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func cliProcess(t *testing.T, dir, scenario string, args ...string) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestReleaseCLIProcess$", "--"}, args...)...)
	command.Dir = dir
	command.Env = append(os.Environ(), "TFPREFLIGHT_RELEASE_PROCESS="+scenario)
	var out, errOut bytes.Buffer
	command.Stdout = &out
	command.Stderr = &errOut
	err := command.Run()
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
		code = exit.ExitCode()
	}
	if ctx.Err() != nil {
		t.Fatal("CLI process hung")
	}
	return code, out.String(), errOut.String()
}

func TestReleaseCLIExitAndJSONContract(t *testing.T) {
	for _, tc := range []struct {
		name           string
		code           int
		classification string
		plan           string
		args           []string
		check          func(*testing.T, report.Document)
	}{
		{name: "clean", code: 0, classification: "completed"},
		{name: "warning", code: 0, classification: "completed"},
		{name: "partial", code: 0, classification: "completed", check: assertUnknownNotFailure},
		{name: "same-plan", code: 0, classification: "completed", check: assertSamePlanCovered},
		{name: "cancel-inspection", code: 0, classification: "completed", check: assertUnknownNotFailure},
		{name: "newer", code: 0, classification: "completed"},
		{name: "newer-blocking", code: 0, classification: "completed"},
		{name: "older", code: 0, classification: "completed"},
		{name: "config", code: 0, classification: "completed"},
		{name: "flag-mismatch", code: 0, classification: "completed", args: []string{"--provider-version=9.0.0"}},
		{name: "blocking", code: 1, classification: "blocking_findings"},
		{name: "dependency-blocking", code: 1, classification: "blocking_findings", check: assertDependencyBlocker},
		{name: "missing-version", code: 2, classification: "tool_error"},
		{name: "multiple-versions", code: 2, classification: "tool_error"},
		{name: "missing-path", code: 2, classification: "tool_error", plan: "absent"},
		{name: "malformed", code: 2, classification: "tool_error"},
		{name: "invalid-envelope", code: 2, classification: "tool_error"},
		{name: "show-error", code: 2, classification: "tool_error"},
		{name: "engine-error", code: 2, classification: "tool_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := cliProject(t, tc.name)
			path := "tfplan"
			if tc.plan != "" {
				path = tc.plan
			}
			args := append([]string{"check", "--plan=" + path, "--format=json", "--debug"}, tc.args...)
			code, out, diagnostics := cliProcess(t, dir, tc.name, args...)
			d := assertCLIContract(t, code, out, diagnostics, tc.code, tc.classification)
			checkSelection(t, tc.name, d)
			if tc.check != nil {
				tc.check(t, d)
			}
		})
	}
}

// assertCLIContract checks what every run promises: the exit code, a JSON
// document with its classification, debug output kept off stdout, and a
// fatal error on stderr for a tool failure.
func assertCLIContract(t *testing.T, code int, out, diagnostics string, wantCode int, classification string) report.Document {
	t.Helper()
	if code != wantCode {
		t.Fatalf("exit=%d want %d\nstdout=%s\nstderr=%s", code, wantCode, out, diagnostics)
	}
	var d report.Document
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("not JSON: %s: %v", out, err)
	}
	if d.SchemaVersion != "1" || d.ExitClassification != classification {
		t.Fatalf("contract: %+v", d)
	}
	if strings.Contains(out, "a debug") {
		t.Fatal("debug contaminated stdout")
	}
	if wantCode == 2 && !strings.Contains(diagnostics, "tfpreflight:") {
		t.Fatal("fatal error missing from stderr")
	}
	return d
}

func assertUnknownNotFailure(t *testing.T, d report.Document) {
	t.Helper()
	if d.Summary.Partial == 0 || d.Summary.Blocking != 0 || len(d.Findings) != 0 {
		t.Fatalf("unknown became failure: %+v", d)
	}
}

func assertSamePlanCovered(t *testing.T, d report.Document) {
	t.Helper()
	if d.Summary.Checked < 1 {
		t.Fatal("same-plan coverage missing")
	}
}

// assertDependencyBlocker requires the blocker to be the real dependency
// finding, produced by the engine's gate rather than injected by the fixture.
func assertDependencyBlocker(t *testing.T, d report.Document) {
	t.Helper()
	var blocker *report.Finding
	for i, f := range d.Findings {
		if f.Category == "dependency" && f.Blocking {
			blocker = &d.Findings[i]
		}
	}
	if blocker == nil {
		t.Fatalf("no blocking dependency finding: %+v", d.Findings)
	}
	if blocker.Severity != "error" || blocker.Confidence != "high" {
		t.Fatalf("blocking dependency finding = %+v", blocker)
	}
	if d.Summary.Blocking != 1 {
		t.Fatalf("summary blocking = %d, want 1", d.Summary.Blocking)
	}
}

func TestReleaseCLIDeterministicStreams(t *testing.T) {
	dir := cliProject(t, "warning")
	type result struct {
		code             int
		out, diagnostics string
	}
	var mu sync.Mutex
	results := map[string]result{}
	// Every run is its own process, so they run side by side and are compared
	// once all have finished.
	t.Run("runs", func(t *testing.T) {
		for _, format := range []string{"text", "json"} {
			for i := 0; i < 5; i++ {
				name := fmt.Sprintf("%s-debug-%d", format, i)
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					code, out, diagnostics := cliProcess(t, dir, "warning", "check", "--plan=tfplan", "--format="+format, "--debug")
					mu.Lock()
					results[name] = result{code, out, diagnostics}
					mu.Unlock()
				})
			}
			t.Run(format+"-quiet", func(t *testing.T) {
				t.Parallel()
				code, out, diagnostics := cliProcess(t, dir, "warning", "check", "--plan=tfplan", "--format="+format)
				mu.Lock()
				results[format+"-quiet"] = result{code, out, diagnostics}
				mu.Unlock()
			})
		}
	})
	for _, format := range []string{"text", "json"} {
		first := results[format+"-debug-0"]
		for i := 1; i < 5; i++ {
			if next := results[fmt.Sprintf("%s-debug-%d", format, i)]; next != first || next.code != 0 {
				t.Fatalf("%s: nondeterministic output", format)
			}
		}
		if quiet := results[format+"-quiet"]; quiet.out != first.out || quiet.diagnostics != "" {
			t.Fatalf("%s: debug changed semantic output", format)
		}
	}
}

func TestReleaseCLIArgumentFailures(t *testing.T) {
	dir := cliProject(t, "clean")
	t.Run("unknown flag", func(t *testing.T) {
		t.Parallel()
		code, out, diagnostics := cliProcess(t, dir, "clean", "check", "--unknown")
		if code != 2 || out != "" || !strings.Contains(diagnostics, "unknown flag") {
			t.Fatalf("invalid arguments: %d %q %q", code, out, diagnostics)
		}
	})
	t.Run("unknown flag, JSON", func(t *testing.T) {
		t.Parallel()
		code, out, _ := cliProcess(t, dir, "clean", "check", "--unknown", "--format=json")
		if code != 2 || !json.Valid([]byte(out)) {
			t.Fatalf("JSON argument failure: %d %s", code, out)
		}
	})
	t.Run("missing plan", func(t *testing.T) {
		t.Parallel()
		code, out, diagnostics := cliProcess(t, dir, "missing-path", "check", "--plan=absent")
		if code != 2 || out != "" || diagnostics == "" {
			t.Fatal("fatal text emitted to stdout")
		}
	})
}

func TestReleaseCLIReportBundleIsRedactedAndPreviewed(t *testing.T) {
	dir := cliProject(t, "warning")
	path := filepath.Join(dir, "tfpreflight-report.json")
	code, out, diagnostics := cliProcess(t, dir, "warning", "check", "--plan=tfplan", "--details", "--report="+path)
	if code != 0 || !strings.Contains(out, "Report a wrong result:") {
		t.Fatalf("code %d\nstdout %s\nstderr %s", code, out, diagnostics)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) || !strings.Contains(diagnostics, string(data)) || !strings.Contains(diagnostics, "Review this file before sharing it.") {
		t.Fatalf("bundle was not shown exactly\nfile %s\nstderr %s", data, diagnostics)
	}
	for _, sensitive := range []string{"aws_subnet.test", "vpc-0123456789abcdef0", "123456789012", "arn:aws"} {
		if bytes.Contains(data, []byte(sensitive)) {
			t.Errorf("default bundle contains %q:\n%s", sensitive, data)
		}
	}
	var bundle report.Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.PackID == "" || bundle.Provider.Version != "6.64.0" || bundle.Provider.Mode != "COVERED" || bundle.Redaction.SensitiveValuesIncluded {
		t.Fatalf("bundle metadata = %+v", bundle)
	}

	fullPath := filepath.Join(dir, "tfpreflight-report-full.json")
	code, _, _ = cliProcess(t, dir, "warning", "check", "--plan=tfplan", "--report="+fullPath, "--report-include-sensitive")
	full, err := os.ReadFile(fullPath)
	if err != nil || code != 0 || !bytes.Contains(full, []byte("aws_subnet.test")) {
		t.Fatalf("full bundle: code=%d err=%v data=%s", code, err, full)
	}

	code, _, diagnostics = cliProcess(t, dir, "warning", "check", "--plan=tfplan", "--report-include-sensitive")
	if code != 2 || !strings.Contains(diagnostics, "requires --report") {
		t.Fatalf("unpaired sensitive flag: code=%d stderr=%s", code, diagnostics)
	}
}

func TestVersionAndHelp(t *testing.T) {
	dir := cliProject(t, "clean")
	code, out, _ := cliProcess(t, dir, "clean", "version")
	if code != 0 || !strings.Contains(out, "(commit ") || strings.Contains(out, "6.64.0") {
		t.Fatalf("version lists versions without --verbose:\n%s", out)
	}
	for _, args := range [][]string{{"--version"}, {"-v"}} {
		if code, flag, _ := cliProcess(t, dir, "clean", args...); code != 0 || flag != out {
			t.Fatalf("%v prints %q, version prints %q", args, flag, out)
		}
	}
	if _, verbose, _ := cliProcess(t, dir, "clean", "version", "--verbose"); !strings.Contains(verbose, "6.64.0") {
		t.Fatalf("--verbose lacks the covered versions:\n%s", verbose)
	}
	_, help, _ := cliProcess(t, dir, "clean", "check", "--help")
	for _, s := range []string{"PARTIAL", "--format", "--principal", "--provider-version", "--report", ".tfpreflight.yml"} {
		if !strings.Contains(help, s) {
			t.Errorf("help missing %s", s)
		}
	}
}

// checkSelection checks how the version was chosen and what it allowed:
// outside COVERED nothing blocks, and a version other than the lock file's
// is called out.
func checkSelection(t *testing.T, scenario string, d report.Document) {
	t.Helper()
	want := map[string]struct{ version, mode, source, lock string }{
		"clean":          {"6.64.0", "COVERED", "lock", "6.64.0"},
		"blocking":       {"6.64.0", "COVERED", "lock", "6.64.0"},
		"newer":          {"9.0.0", "NEWER", "lock", "9.0.0"},
		"newer-blocking": {"9.0.0", "NEWER", "lock", "9.0.0"},
		"older":          {"5.50.0", "OLDER", "lock", "5.50.0"},
		"config":         {"6.64.0", "COVERED", "config", "9.0.0"},
		"flag-mismatch":  {"9.0.0", "NEWER", "flag", "6.64.0"},
	}
	w, ok := want[scenario]
	if !ok {
		return
	}
	p := d.Provider
	if p.Version != w.version || p.Mode != w.mode || p.VersionSource != w.source || p.LockVersion != w.lock || p.RulesVersion == "" {
		t.Fatalf("provider = %+v, want %+v", p, w)
	}
	if w.mode != "COVERED" {
		assertNothingBlocks(t, scenario, d)
	}
	if scenario == "newer-blocking" || scenario == "older" {
		if !hasFinding(d, func(f report.Finding) bool { return f.ID == "synthetic" && f.Severity == "warning" }) {
			t.Fatalf("the would-be blocker is not a warning: %+v", d.Findings)
		}
	}
	mismatch := hasFinding(d, func(f report.Finding) bool { return f.ID == "provider-version-mismatch" })
	if mismatch != (w.version != w.lock) {
		t.Fatalf("mismatch finding = %v for version %s, lock %s", mismatch, w.version, w.lock)
	}
}

// assertNothingBlocks checks every finding is downgraded outside COVERED.
func assertNothingBlocks(t *testing.T, scenario string, d report.Document) {
	t.Helper()
	if d.Summary.Blocking != 0 {
		t.Fatalf("%s blocked outside COVERED: %+v", scenario, d.Findings)
	}
	for _, f := range d.Findings {
		if f.Blocking || f.Severity == "error" {
			t.Fatalf("finding not downgraded: %+v", f)
		}
	}
}

func hasFinding(d report.Document, match func(report.Finding) bool) bool {
	for _, f := range d.Findings {
		if match(f) {
			return true
		}
	}
	return false
}
