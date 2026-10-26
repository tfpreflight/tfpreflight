//go:build unix

package plan

import (
	"os/exec"
	"syscall"
)

// ownProcessGroup starts the command in a process group of its own, so a
// Ctrl-C at the terminal reaches only tfpreflight, which passes on one
// interrupt. Terraform reads a second interrupt as "exit now", which could
// leave a state lock behind.
func ownProcessGroup(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup kills the tool and anything it started.
func killProcessGroup(command *exec.Cmd) {
	if command.Process != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
}
