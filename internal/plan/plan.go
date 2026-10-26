package plan

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// CommandError preserves Terraform or OpenTofu diagnostics from a failed command.
type CommandError struct {
	Operation   string
	Diagnostics string
	Err         error
}

// Error returns the failed command's message.
func (e *CommandError) Error() string {
	if e.Diagnostics != "" {
		return e.Operation + " failed: " + e.Diagnostics
	}
	return e.Operation + " failed"
}

// Unwrap returns the command failure.
func (e *CommandError) Unwrap() error { return e.Err }

// GeneratePlan creates a temporary plan with tool. The caller must call cleanup.
// On any error, cancellation included, nothing is left behind.
func GeneratePlan(ctx context.Context, tool Tool) (planPath string, cleanup func(), err error) {
	directory, err := os.MkdirTemp("", "tfpreflight-plan-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temporary plan directory: %w", err)
	}
	untrack := trackDir(directory)
	cleanup = func() {
		_ = os.RemoveAll(directory)
		untrack()
	}
	planPath = filepath.Join(directory, "plan.tfplan")

	if err := runTool(ctx, tool, "plan", "-input=false", "-no-color", "-out="+planPath); err != nil {
		cleanup()
		return "", nil, err
	}
	return planPath, cleanup, nil
}

// ValidatePlanFile checks that path is an existing file, not a directory.
func ValidatePlanFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("plan file %q: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("plan file %q is a directory", path)
	}
	return nil
}

// ShowPlanJSON returns the plan as `show -json` prints it.
func ShowPlanJSON(ctx context.Context, tool Tool, planPath string) ([]byte, error) {
	stdout, stderr, err := runCommand(toolCommand(ctx, tool.Path, "show", "-json", "-no-color", planPath))
	if err != nil {
		return nil, commandError(ctx, "Terraform/OpenTofu show", stdout, stderr, err)
	}
	return stdout, nil
}

func runTool(ctx context.Context, tool Tool, args ...string) error {
	stdout, stderr, err := runCommand(toolCommand(ctx, tool.Path, args...))
	if err != nil {
		return commandError(ctx, "Terraform/OpenTofu "+args[0], stdout, stderr, err)
	}
	return nil
}

// waitDelay is how long Terraform or OpenTofu has to stop after an
// interrupt before it is killed: long enough to release a state lock.
var waitDelay = 30 * time.Second

// toolCommand runs Terraform or OpenTofu as automation. Cancelling ctx sends
// it an interrupt, as Ctrl-C would, so it stops cleanly and releases any
// state lock; it is killed only if it has not exited after waitDelay.
func toolCommand(ctx context.Context, path string, args ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, path, args...)
	command.Env = append(os.Environ(), "TF_IN_AUTOMATION=1")
	command.Cancel = func() error {
		if err := command.Process.Signal(os.Interrupt); err != nil {
			return command.Process.Kill()
		}
		return nil
	}
	command.WaitDelay = waitDelay
	ownProcessGroup(command)
	return command
}

func runCommand(command *exec.Cmd) (stdout, stderr []byte, err error) {
	var output, diagnostics bytes.Buffer
	command.Stdout = &output
	command.Stderr = &diagnostics
	if err = command.Start(); err != nil {
		return nil, nil, err
	}
	untrack := trackCommand(command)
	err = command.Wait()
	untrack()
	return output.Bytes(), diagnostics.Bytes(), err
}

// commandError reports a failed command. A command stopped because ctx was
// cancelled reports the interruption, not the failure it caused.
func commandError(ctx context.Context, operation string, stdout, stderr []byte, err error) error {
	if ctx.Err() != nil {
		return interrupted(ctx)
	}
	diagnostics := string(bytes.TrimSpace(stderr))
	if diagnostics == "" {
		diagnostics = string(bytes.TrimSpace(stdout))
	}
	return &CommandError{Operation: operation, Diagnostics: diagnostics, Err: err}
}

// interrupted is the error for work ctx stopped. It matches ctx.Err() and
// the cause with errors.Is, and names the cause, such as the signal received.
func interrupted(ctx context.Context) error {
	return &interruptedError{err: ctx.Err(), cause: context.Cause(ctx)}
}

type interruptedError struct{ err, cause error }

// Error describes the interruption and its cause.
func (e *interruptedError) Error() string { return "interrupted (" + e.cause.Error() + ")" }

// Unwrap returns the interruption and its cause.
func (e *interruptedError) Unwrap() []error { return []error{e.err, e.cause} }
