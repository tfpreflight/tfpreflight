package plan

import (
	"os"
	"os/exec"
	"sync"
)

// running is what Abort has to undo: tool processes still running and
// temporary plan directories not yet removed.
var running = struct {
	sync.Mutex
	commands map[*exec.Cmd]bool
	dirs     map[string]bool
}{commands: map[*exec.Cmd]bool{}, dirs: map[string]bool{}}

// Abort kills every running Terraform or OpenTofu process and removes every
// temporary plan, for a caller about to exit without waiting for them.
func Abort() {
	running.Lock()
	defer running.Unlock()
	for command := range running.commands {
		killProcessGroup(command)
	}
	for dir := range running.dirs {
		_ = os.RemoveAll(dir)
	}
}

func track(set func(), unset func()) func() {
	running.Lock()
	set()
	running.Unlock()
	return func() {
		running.Lock()
		unset()
		running.Unlock()
	}
}

func trackCommand(command *exec.Cmd) func() {
	return track(func() { running.commands[command] = true }, func() { delete(running.commands, command) })
}

func trackDir(dir string) func() {
	return track(func() { running.dirs[dir] = true }, func() { delete(running.dirs, dir) })
}
