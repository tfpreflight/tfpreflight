package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/tfpreflight/tfpreflight/internal/check"
	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/internal/report"
)

// Version is the release version injected at build time.
var Version = "dev"

// Commit is the source revision injected at build time.
var Commit = "unknown"

func newRootCommand() *cobra.Command {
	root := rootWithServices(check.Production())
	useName(root, invokedName(os.Args[0]))
	return root
}

func rootWithServices(deps check.Dependencies) *cobra.Command {
	var showVersion, verbose bool
	command := &cobra.Command{
		Use:   "tfpreflight",
		Short: "Find what would make terraform apply fail, before you run it",
		Long: `tfpreflight reads a Terraform or OpenTofu plan and makes read-only calls to AWS
to find what would make the apply fail: a missing permission, a name that is
already taken, a resource the plan points at that does not exist, a quota the
plan would exceed. It also says what it could not check.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if showVersion {
				return writeVersion(command.OutOrStdout(), verbose)
			}
			return command.Help()
		},
		PersistentPreRunE: func(command *cobra.Command, _ []string) error { return useRules(command) },
	}
	command.PersistentFlags().String("pack-dir", "", "read rules from this directory instead of the built-in ones (it must hold aws/manifest.json)")
	command.Flags().BoolVarP(&showVersion, "version", "v", false, "show the same information as tfpreflight version")
	command.Flags().BoolVar(&verbose, "verbose", false, "with --version, also list every covered AWS provider version")
	command.AddCommand(checkCommand(deps))
	command.AddCommand(versionCommand())
	command.AddCommand(updateCommand())
	return command
}

// useRules chooses the rules once, before a command runs: --pack-dir, else the
// newest valid downloaded bundle, else the built-in rules. A --pack-dir set
// that fails validation is a tool failure; a bad downloaded bundle is ignored
// with a warning.
func useRules(command *cobra.Command) error {
	packDir, _ := command.Flags().GetString("pack-dir")
	set, warnings, err := packs.Select(packDir)
	for _, warning := range warnings {
		_, _ = fmt.Fprintln(command.ErrOrStderr(), "tfpreflight: warning:", warning)
	}
	if err != nil {
		return toolFailure(fmt.Errorf("load rules: %w", err))
	}
	packs.Use(set)
	return nil
}

func runRoot(ctx context.Context, c *cobra.Command, args []string, out, diagnostics io.Writer) int {
	destination := &resultWriter{Writer: out}
	c.SetArgs(args)
	c.SetOut(destination)
	c.SetErr(diagnostics)
	c.SetContext(ctx)
	err := c.Execute()
	if err != nil && destination.bytes == 0 && jsonRequested(args) {
		supported, _ := packs.AWS()
		errorReport := report.Normalize(report.Input{SupportedVersions: supported})
		if outputErr := report.WriteJSON(destination, errorReport.Document(err)); outputErr != nil {
			err = toolFailure(fmt.Errorf("write JSON error report: %w", outputErr))
		}
	}
	if destination.err != nil {
		err = toolFailure(fmt.Errorf("write command output: %w", destination.err))
	}
	code := exitCode(err)
	if code == exitToolFailure {
		_, _ = fmt.Fprintln(diagnostics, "tfpreflight:", err)
	}
	return code
}

type resultWriter struct {
	io.Writer
	bytes int
	err   error
}

// Write stores report output while passing it to the command writer.
func (w *resultWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	w.bytes += n
	if err != nil && w.err == nil {
		w.err = err
	}
	return n, err
}

// jsonRequested reports whether args ask for JSON. A run whose flags did not
// parse still owes a JSON caller a JSON error, and cobra stops parsing at the
// first bad flag.
func jsonRequested(args []string) bool {
	flags := pflag.NewFlagSet("format", pflag.ContinueOnError)
	flags.ParseErrorsAllowlist.UnknownFlags = true
	flags.SetOutput(io.Discard)
	format := flags.String("format", "", "")
	_ = flags.Parse(args)
	return *format == "json"
}
