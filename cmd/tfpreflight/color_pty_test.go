//go:build unix

package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/creack/pty"
)

// A Terraform that plans nothing, so the check needs no cloud account and
// prints "! Nothing could be checked.", a line that is yellow in a terminal.
const emptyPlanTerraform = `#!/bin/sh
case $1 in
version) echo "Terraform v1.12.0" ;;
plan) for arg in "$@"; do case $arg in -out=*) echo plan > "${arg#-out=}" ;; esac; done ;;
show) echo '{"format_version":"1.2","terraform_version":"1.12.0","planned_values":{"root_module":{}},"resource_changes":[],"configuration":{"root_module":{}}}' ;;
*) exit 1 ;;
esac
`

const yellowResult = "\x1b[33m! Nothing could be checked.\x1b[0m"

// buildBinary builds the real program, as a release does, and gives it both of
// its names. Color has to work in that binary: tests of the pieces passed while
// the released beta.3 printed no color at all, because the command's writer
// hid the terminal from the check.
func buildBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if out, err := exec.Command("go", "build", "-o", filepath.Join(dir, "tfpreflight"), ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	if err := os.Symlink("tfpreflight", filepath.Join(dir, "tfp")); err != nil {
		t.Fatal(err)
	}
	return dir
}

// runBuilt runs the built binary in a temporary project with a fake Terraform.
// On a terminal it gets a pseudo-terminal; otherwise its output goes to a pipe.
func runBuilt(t *testing.T, bin, name string, onTerminal bool, env []string, args ...string) string {
	t.Helper()
	tools, work := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(tools, "terraform"), []byte(emptyPlanTerraform), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "main.tf"), []byte("# nothing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(filepath.Join(bin, name), append([]string{"check"}, args...)...)
	command.Dir = work
	command.Env = append([]string{
		"PATH=" + tools + ":/usr/bin:/bin",
		"HOME=" + t.TempDir(),
		"AWS_EC2_METADATA_DISABLED=true",
		"AWS_CONFIG_FILE=" + os.DevNull,
		"AWS_SHARED_CREDENTIALS_FILE=" + os.DevNull,
	}, env...)
	var output bytes.Buffer
	if onTerminal {
		master, err := pty.Start(command)
		if err != nil {
			t.Fatal(err)
		}
		defer master.Close()
		_, _ = io.Copy(&output, master) // ends with an error when the program exits
		_ = command.Wait()
	} else {
		command.Stdout = &output
		_ = command.Run()
	}
	return output.String()
}

func TestBuiltBinaryColorsOnATerminal(t *testing.T) {
	bin := buildBinary(t)
	for _, name := range []string{"tfpreflight", "tfp"} {
		for caseName, tc := range map[string]struct {
			env     []string
			args    []string
			onTTY   bool
			colored bool
		}{
			"terminal":                  {[]string{"TERM=xterm-256color"}, nil, true, true},
			"NO_COLOR set":              {[]string{"TERM=xterm", "NO_COLOR=1"}, nil, true, false},
			"NO_COLOR empty is not set": {[]string{"TERM=xterm", "NO_COLOR="}, nil, true, true},
			"TERM dumb":                 {[]string{"TERM=dumb"}, nil, true, false},
			"piped":                     {[]string{"TERM=xterm"}, nil, false, false},
			"JSON on a terminal":        {[]string{"TERM=xterm"}, []string{"--format=json"}, true, false},
			"details on a terminal":     {[]string{"TERM=xterm"}, []string{"--details"}, true, false},
		} {
			t.Run(name+"/"+caseName, func(t *testing.T) {
				got := runBuilt(t, bin, name, tc.onTTY, tc.env, tc.args...)
				if tc.colored {
					if !strings.Contains(got, yellowResult) {
						t.Errorf("no color on a terminal; output %q", got)
					}
				} else if strings.Contains(got, "\x1b[") {
					t.Errorf("escape codes where there should be none: %q", got)
				}
				if got == "" {
					t.Error("no output")
				}
			})
		}
	}
}
