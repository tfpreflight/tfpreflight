package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tfpreflight/tfpreflight/internal/packs"
)

func versionCommand() *cobra.Command {
	var verbose bool
	command := &cobra.Command{
		Use: "version", Short: "Show the version and the AWS provider versions its rules cover", Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return writeVersion(command.OutOrStdout(), verbose)
		},
	}
	command.Flags().BoolVar(&verbose, "verbose", false, "also list every covered AWS provider version")
	return command
}

// writeVersion is the output of both version and --version.
func writeVersion(out io.Writer, verbose bool) error {
	set, err := packs.Active()
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	info := set.Info()
	var b strings.Builder
	fmt.Fprintf(&b, "tfpreflight %s (commit %s)\n", Version, Commit)
	fmt.Fprintf(&b, "Rules: %s\n", packsLine(info))
	if n := len(info.Versions); n > 0 {
		fmt.Fprintf(&b, "AWS provider rules: %d exact versions, %s to %s\n", n, info.Versions[0], info.Versions[n-1])
		for _, gap := range coverageGaps(info.Versions) {
			fmt.Fprintf(&b, "  no rules between %s and %s\n", gap[0], gap[1])
		}
		b.WriteString("Other versions are checked with the nearest rules, as warnings only.\n")
	}
	if verbose {
		fmt.Fprintf(&b, "Covered versions: %s\n", strings.Join(info.Versions, ", "))
	}
	if _, err := io.WriteString(out, b.String()); err != nil {
		return fmt.Errorf("write version information: %w", err)
	}
	return nil
}

func packsLine(info packs.Info) string {
	switch info.Origin {
	case packs.OriginCache:
		return "bundle " + info.ID + " from " + info.Location
	case packs.OriginDir:
		return "--pack-dir " + info.Location
	}
	return "built in"
}

// coverageGaps are the pairs of neighbouring covered versions with at least a
// whole minor release between them. Missing patch releases are not listed: not
// every patch is covered, and those are not the gaps a reader would miss.
func coverageGaps(versions []string) [][2]string {
	var gaps [][2]string
	for i := 1; i < len(versions); i++ {
		previous, next := majorMinor(versions[i-1]), majorMinor(versions[i])
		if next[0] != previous[0] && next[1] != 0 || next[0] == previous[0] && next[1] > previous[1]+1 {
			gaps = append(gaps, [2]string{versions[i-1], versions[i]})
		}
	}
	return gaps
}

func majorMinor(version string) [2]int {
	parts := strings.SplitN(version, ".", 3)
	var mm [2]int
	for i := 0; i < 2 && i < len(parts); i++ {
		mm[i], _ = strconv.Atoi(parts[i])
	}
	return mm
}
