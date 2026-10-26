//go:build !windows

package plan

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeTerraform is a terraform executable whose behaviour the test picks:
//
//	ok        plan writes its -out file, show prints a plan
//	fail      prints a diagnostic and exits 1
//	hang      waits until interrupted, records the interrupt, exits 130
//	stubborn  ignores interrupts and waits forever
//
// It logs its arguments and TF_IN_AUTOMATION, and writes its PID once it is
// running.
const fakeTerraform = `#!/bin/sh
dir=$(dirname "$0")
echo "$* TF_IN_AUTOMATION=$TF_IN_AUTOMATION" >> "$dir/args"
case $(cat "$dir/mode") in
ok)
  for arg in "$@"; do
    case $arg in -out=*) echo plan > "${arg#-out=}" ;; esac
  done
  [ "$1" = show ] && echo '{"format_version":"1.2"}'
  exit 0 ;;
fail)
  echo "Error: No value for required variable" >&2
  exit 1 ;;
hang)
  trap 'echo INT >> "$dir/signals"; exit 130' INT
  echo $$ > "$dir/pid"
  while :; do sleep 0.1; done ;;
stubborn)
  trap '' INT
  echo $$ > "$dir/pid"
  while :; do sleep 0.1; done ;;
esac
`

// processTest is a fake terraform in mode, and an empty temporary directory
// for the plans it generates.
type processTest struct {
	dir  string
	tool Tool
	temp string
}

func newProcessTest(t *testing.T, mode string) processTest {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "terraform"), []byte(fakeTerraform), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mode"), []byte(mode), 0o644); err != nil {
		t.Fatal(err)
	}
	temp := filepath.Join(dir, "tmp")
	if err := os.Mkdir(temp, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", temp)
	return processTest{dir: dir, tool: Tool{Kind: Terraform, Name: "Terraform", Path: filepath.Join(dir, "terraform")}, temp: temp}
}

func (p processTest) read(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(p.dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// assertNoPlanLeft fails if any generated plan is still on disk.
func (p processTest) assertNoPlanLeft(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(p.temp)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary plan left behind: %v", entries)
	}
}

// cancelOnceRunning cancels ctx, as a signal would, once the fake has
// written its PID.
func (p processTest) cancelOnceRunning(cancel context.CancelCauseFunc) {
	go func() {
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if pidWritten(filepath.Join(p.dir, "pid")) {
				break
			}
		}
		cancel(errors.New("terminated signal received"))
	}()
}

func TestGeneratePlanRunsAsAutomation(t *testing.T) {
	p := newProcessTest(t, "ok")
	path, cleanup, err := GeneratePlan(context.Background(), p.tool)
	if err != nil {
		t.Fatal(err)
	}
	want := "plan -input=false -no-color -out=" + path + " TF_IN_AUTOMATION=1\n"
	if got := p.read(t, "args"); got != want {
		t.Fatalf("terraform ran as %q, want %q", got, want)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("plan not written: %v", err)
	}
	cleanup()
	p.assertNoPlanLeft(t)
}

func TestShowPlanJSONReturnsTheDocument(t *testing.T) {
	p := newProcessTest(t, "ok")
	data, err := ShowPlanJSON(context.Background(), p.tool, "plan.tfplan")
	if err != nil || strings.TrimSpace(string(data)) != `{"format_version":"1.2"}` {
		t.Fatalf("show = %q, %v", data, err)
	}
	if got := p.read(t, "args"); got != "show -json -no-color plan.tfplan TF_IN_AUTOMATION=1\n" {
		t.Fatalf("terraform ran as %q", got)
	}
}

// A failed command keeps its diagnostics and exit status, and a failed plan
// leaves nothing behind.
func TestFailedCommandsReportTerraformsDiagnostics(t *testing.T) {
	for name, run := range map[string]func(Tool) error{
		"plan": func(tool Tool) error { _, _, err := GeneratePlan(context.Background(), tool); return err },
		"show": func(tool Tool) error { _, err := ShowPlanJSON(context.Background(), tool, "plan.tfplan"); return err },
	} {
		t.Run(name, func(t *testing.T) {
			p := newProcessTest(t, "fail")
			err := run(p.tool)
			var failed *CommandError
			if !errors.As(err, &failed) || failed.Diagnostics != "Error: No value for required variable" {
				t.Fatalf("err = %v, want Terraform's diagnostic", err)
			}
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Fatalf("err = %v, want exit status 1", err)
			}
			p.assertNoPlanLeft(t)
		})
	}
}

// Cancelling a run interrupts Terraform, once, instead of killing it, says
// the run was interrupted, and removes the temporary plan.
func TestCancelInterruptsTerraformAndRemovesThePlan(t *testing.T) {
	for name, run := range map[string]func(context.Context, Tool) error{
		"plan": func(ctx context.Context, tool Tool) error { _, _, err := GeneratePlan(ctx, tool); return err },
		"show": func(ctx context.Context, tool Tool) error {
			_, err := ShowPlanJSON(ctx, tool, "plan.tfplan")
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := newProcessTest(t, "hang")
			ctx, cancel := context.WithCancelCause(context.Background())
			p.cancelOnceRunning(cancel)
			err := run(ctx, p.tool)
			if !errors.Is(err, context.Canceled) || err.Error() != "interrupted (terminated signal received)" {
				t.Fatalf("err = %v, want an interruption", err)
			}
			if got := p.read(t, "signals"); got != "INT\n" {
				t.Fatalf("terraform received %q, want one interrupt", got)
			}
			assertProcessGone(t, filepath.Join(p.dir, "pid"))
			p.assertNoPlanLeft(t)
		})
	}
}

// A Terraform that ignores the interrupt is killed after waitDelay.
func TestCancelKillsTerraformThatIgnoresTheInterrupt(t *testing.T) {
	defer func(previous time.Duration) { waitDelay = previous }(waitDelay)
	waitDelay = 200 * time.Millisecond
	p := newProcessTest(t, "stubborn")
	ctx, cancel := context.WithCancelCause(context.Background())
	p.cancelOnceRunning(cancel)
	started := time.Now()
	_, _, err := GeneratePlan(ctx, p.tool)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want an interruption", err)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("returned after %s; terraform was not killed", elapsed)
	}
	assertProcessGone(t, filepath.Join(p.dir, "pid"))
	p.assertNoPlanLeft(t)
}
