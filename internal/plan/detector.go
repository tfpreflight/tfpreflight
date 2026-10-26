// Package plan finds Terraform or OpenTofu, runs it to produce and show a
// plan, and parses the plan JSON and provider configuration the checks read.
package plan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ErrToolNotFound indicates that no requested executable is on PATH.
var ErrToolNotFound = errors.New("terraform or tofu executable not found")

// ToolEnv chooses the tool when --tool does not.
const ToolEnv = "TFPREFLIGHT_TOOL"

// binaries maps each tool to its executable, which is also the name --tool
// takes.
var binaries = map[ToolKind]string{Terraform: "terraform", OpenTofu: "tofu"}

// ToolOrder is the tools to look for, in order. A requested tool,
// "terraform" or "tofu", is the only one accepted. Otherwise OpenTofu comes
// first when the lock file takes providers from its registry, and Terraform
// first when it does not: running one on the other's project fails.
func ToolOrder(requested, lockPath string) ([]ToolKind, error) {
	for kind, binary := range binaries {
		if requested == binary {
			return []ToolKind{kind}, nil
		}
	}
	if requested != "" {
		return nil, fmt.Errorf("tool %q: must be terraform or tofu", requested)
	}
	if tofu, err := LockNamesOpenTofu(lockPath); err == nil && tofu {
		return []ToolKind{OpenTofu, Terraform}, nil
	}
	return []ToolKind{Terraform, OpenTofu}, nil
}

// Detect finds the first of tools on PATH and reads its version, which ctx
// can cancel.
func Detect(ctx context.Context, tools []ToolKind) (Tool, error) {
	return detect(ctx, tools, exec.LookPath, versionFor)
}

func detect(ctx context.Context, tools []ToolKind, lookPath func(string) (string, error), getVersion func(context.Context, string) (string, error)) (Tool, error) {
	var looked []string
	for _, kind := range tools {
		binary := binaries[kind]
		looked = append(looked, binary)
		path, err := lookPath(binary)
		if err != nil {
			continue
		}
		version, err := getVersion(ctx, path)
		if err != nil {
			return Tool{}, err
		}
		return Tool{Kind: kind, Name: string(kind), Path: path, Version: version}, nil
	}
	return Tool{}, fmt.Errorf("%w: looked for %s on PATH", ErrToolNotFound, strings.Join(looked, " and "))
}

// HasConfiguration reports whether directory contains at least one .tf file.
func HasConfiguration(directory string) (bool, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".tf" {
			return true, nil
		}
	}
	return false, nil
}
