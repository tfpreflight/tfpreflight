//go:build !unix

package plan

import "os/exec"

func ownProcessGroup(*exec.Cmd) {}

func killProcessGroup(command *exec.Cmd) {
	if command.Process != nil {
		_ = command.Process.Kill()
	}
}
