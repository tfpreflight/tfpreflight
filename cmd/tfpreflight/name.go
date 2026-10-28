package main

import (
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

const (
	longName  = "tfpreflight"
	shortName = "tfp"
)

// invokedName is the name the program was started as: tfp when run through
// the tfp link that Homebrew and install.sh create, tfpreflight otherwise.
func invokedName(arg0 string) string {
	if strings.TrimSuffix(filepath.Base(arg0), ".exe") == shortName {
		return shortName
	}
	return longName
}

// useName makes the usage lines and examples show the name the program was
// started as, so "tfp check --help" reads "tfp check". Messages, flag help
// and the version line keep tfpreflight, the program's name.
func useName(root *cobra.Command, name string) {
	if name == longName {
		return
	}
	root.Use = name
	var rename func(*cobra.Command)
	rename = func(command *cobra.Command) {
		command.Example = strings.ReplaceAll(command.Example, longName+" ", name+" ")
		for _, sub := range command.Commands() {
			rename(sub)
		}
	}
	rename(root)
}
