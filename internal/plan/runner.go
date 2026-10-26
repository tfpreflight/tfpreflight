package plan

import (
	"context"
	"fmt"
	"strings"
)

// ToolKind is Terraform or OpenTofu.
type ToolKind string

// Supported tools.
const (
	Terraform ToolKind = "Terraform"
	OpenTofu  ToolKind = "OpenTofu"
)

// Tool is a Terraform or OpenTofu executable found on PATH.
type Tool struct {
	Kind    ToolKind
	Name    string
	Path    string
	Version string
}

func versionFor(ctx context.Context, path string) (string, error) {
	output, _, err := runCommand(toolCommand(ctx, path, "version"))
	if err != nil {
		// A cancelled command fails with the signal that stopped it; the
		// cancellation is the cause worth reporting.
		if ctx.Err() != nil {
			err = interrupted(ctx)
		}
		return "", fmt.Errorf("run version command: %w", err)
	}

	version := parseVersion(string(output))
	if version == "" {
		return "", fmt.Errorf("version command returned no recognizable version")
	}
	return version, nil
}

func parseVersion(output string) string {
	for _, field := range strings.Fields(output) {
		candidate := strings.TrimPrefix(field, "v")
		if strings.Count(candidate, ".") >= 1 && len(candidate) > 1 && candidate[0] >= '0' && candidate[0] <= '9' {
			return candidate
		}
	}
	return ""
}
