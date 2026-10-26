//go:build !windows

package plan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Cancelling the caller's context stops the tool's version command, and the
// error says the command was cancelled.
func TestDetectCancellationStopsTheVersionCommand(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "pid")
	script := "#!/bin/sh\necho $$ > '" + pidFile + "'\nexec sleep 60\n"
	if err := os.WriteFile(filepath.Join(dir, "terraform"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":/usr/bin:/bin")
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if pidWritten(pidFile) {
				break
			}
		}
		cancel()
	}()
	started := time.Now()
	_, err := Detect(ctx, []ToolKind{Terraform})
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "run version command: interrupted (context canceled)") {
		t.Fatalf("Detect error = %v, want the version command cancelled", err)
	}
	if elapsed := time.Since(started); elapsed > 20*time.Second {
		t.Fatalf("Detect returned after %s; cancellation did not stop the command", elapsed)
	}
	assertProcessGone(t, pidFile)
}

// pidWritten reports whether a script has written its whole PID. The shell
// creates a redirected file before writing to it, so the file existing is not
// enough; echo writes the PID and its newline at once.
func pidWritten(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil || !strings.HasSuffix(string(data), "\n") {
		return false
	}
	_, err = strconv.Atoi(strings.TrimSpace(string(data)))
	return err == nil
}

func assertProcessGone(t *testing.T, pidFile string) {
	t.Helper()
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("version command %d still running after cancellation (kill 0: %v)", pid, err)
	}
}
