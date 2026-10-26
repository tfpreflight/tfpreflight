package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/check"
	"github.com/tfpreflight/tfpreflight/internal/plan"
	"github.com/tfpreflight/tfpreflight/internal/report"
)

func TestBlockingFindingsAndExitCodes(t *testing.T) {
	blocking := checkOutcome{Report: report.Report{Summary: report.Summary{Blocking: 1}}}.commandError()
	if exitCode(nil) != 0 || exitCode(blocking) != 1 || exitCode(errors.New("broken")) != 2 {
		t.Fatal("unexpected exit code mapping")
	}
}

// A pack set that fails validation stops the run with exit 2 and a JSON error
// document; tfpreflight never falls back to the built-in rules.
func TestInvalidPackDirIsAToolFailure(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "aws"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "aws", "manifest.json"), []byte(`{"schema_version":1,"provider":"aws","files":{"aws/x.json":"00"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, diagnostics bytes.Buffer
	code := runRoot(context.Background(), rootWithServices(check.Production()), []string{"--pack-dir", dir, "check", "--format", "json"}, &out, &diagnostics)
	if code != 2 || !strings.Contains(diagnostics.String(), "load rules") || !strings.Contains(out.String(), `"exit_classification": "tool_error"`) {
		t.Fatalf("code %d\nstdout %s\nstderr %s", code, out.String(), diagnostics.String())
	}
}

// --tool takes terraform or tofu, and TFPREFLIGHT_TOOL is read when the flag
// is not given.
func TestUnknownToolIsAToolFailure(t *testing.T) {
	dir := cliProject(t, "clean")
	code, _, diagnostics := cliProcess(t, dir, "clean", "check", "--plan=tfplan", "--tool=opentofu")
	if code != 2 || !strings.Contains(diagnostics, `tool "opentofu": must be terraform or tofu`) {
		t.Fatalf("--tool: code %d, stderr %s", code, diagnostics)
	}
	t.Setenv(plan.ToolEnv, "pulumi")
	code, _, diagnostics = cliProcess(t, dir, "clean", "check", "--plan=tfplan")
	if code != 2 || !strings.Contains(diagnostics, `tool "pulumi": must be terraform or tofu`) {
		t.Fatalf("%s: code %d, stderr %s", plan.ToolEnv, code, diagnostics)
	}
}

func TestJSONRequested(t *testing.T) {
	for args, want := range map[string]bool{
		"check --format=json":                    true,
		"check --format json":                    true,
		"check --unknown --format=json":          true,
		"check --plan=json --format=text":        false,
		"check --plan json":                      false,
		"check --format=json --format=text":      false,
		"--pack-dir dir check --format json --x": true,
	} {
		if got := jsonRequested(strings.Fields(args)); got != want {
			t.Errorf("jsonRequested(%q) = %v, want %v", args, got, want)
		}
	}
}
