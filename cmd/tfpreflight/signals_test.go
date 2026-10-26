//go:build unix

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeTerraform reports a version, and on plan writes its -out file, then
// records each interrupt and keeps running: a Terraform slow to stop.
const signalsTerraform = `#!/bin/sh
dir=$(dirname "$0")
case $1 in
version) echo "Terraform v1.12.0"; exit 0 ;;
plan)
  trap 'echo INT >> "$dir/signals"' INT
  for arg in "$@"; do
    case $arg in -out=*) echo plan > "${arg#-out=}" ;; esac
  done
  echo $$ > "$dir/pid"
  while :; do sleep 0.1; done ;;
esac
exit 1
`

// The first signal interrupts Terraform and waits for it. A second kills it,
// removes the temporary plan, and exits 130 straight away.
func TestSecondSignalStopsAtOnce(t *testing.T) {
	for name, sig := range map[string]syscall.Signal{"SIGINT": syscall.SIGINT, "SIGTERM": syscall.SIGTERM} {
		t.Run(name, func(t *testing.T) { stopWithTwoSignals(t, sig) })
	}
}

func stopWithTwoSignals(t *testing.T, sig syscall.Signal) {
	t.Helper()
	tool, temp := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(tool, "terraform"), []byte(signalsTerraform), 0o755); err != nil {
		t.Fatal(err)
	}
	dir := cliProject(t, "clean")
	command := exec.Command(os.Args[0], "-test.run=^TestReleaseCLIProcess$", "--", "check")
	command.Dir = dir
	command.Env = append(os.Environ(), "TFPREFLIGHT_RELEASE_PROCESS=signals", "PATH="+tool+":/usr/bin:/bin", "TMPDIR="+temp)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()

	waitFor(t, func() bool { return pidWritten(filepath.Join(tool, "pid")) }, "terraform plan to start")
	if err := command.Process.Signal(sig); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { data, _ := os.ReadFile(filepath.Join(tool, "signals")); return string(data) == "INT\n" }, "terraform to receive one interrupt")
	select {
	case err := <-exited:
		t.Fatalf("exited after the first signal (%v); it must wait for terraform", err)
	case <-time.After(300 * time.Millisecond):
	}

	if err := command.Process.Signal(sig); err != nil {
		t.Fatal(err)
	}
	var err error
	select {
	case err = <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("still running 5s after the second signal")
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != exitInterrupted {
		t.Fatalf("exit = %v, want %d", err, exitInterrupted)
	}
	waitFor(t, func() bool { return processGone(t, filepath.Join(tool, "pid")) }, "terraform to be killed")
	if plans, _ := filepath.Glob(filepath.Join(temp, "tfpreflight-plan-*")); len(plans) != 0 {
		t.Fatalf("temporary plan left behind: %v", plans)
	}
}

func waitFor(t *testing.T, done func() bool, what string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if done() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// pidWritten reports whether the fake terraform has written its whole PID. The
// shell creates a redirected file before writing to it, so the file existing
// is not enough; echo writes the PID and its newline at once.
func pidWritten(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil || !strings.HasSuffix(string(data), "\n") {
		return false
	}
	_, err = strconv.Atoi(strings.TrimSpace(string(data)))
	return err == nil
}

func processGone(t *testing.T, pidFile string) bool {
	t.Helper()
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
}
