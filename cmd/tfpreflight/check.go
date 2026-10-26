// Command tfpreflight predicts Terraform and OpenTofu apply failures it can
// prove or inspect before apply. A clean run describes only the checks that
// ran; it is not a guarantee that the apply will succeed.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/tfpreflight/tfpreflight/internal/check"
	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/internal/plan"
	"github.com/tfpreflight/tfpreflight/internal/report"
)

type renderFormat string

const (
	formatText renderFormat = "text"
	formatJSON renderFormat = "json"
)

type checkOptions struct {
	check.Request
	Format          renderFormat
	All             bool
	Details         bool
	Debug           bool
	ReportPath      string
	ReportSensitive bool
	Update          bool
}

const checkLong = `Check a Terraform or OpenTofu plan for apply failures tfpreflight can predict.

Without --plan, tfpreflight generates a temporary plan and removes it afterwards.
AWS inspection uses your normal AWS SDK credentials; --principal only names the
IAM identity whose permissions are simulated.

The AWS provider version comes from --provider-version, else provider_version in
.tfpreflight.yml, else .terraform.lock.hcl. A version without rules of its own is
checked with the nearest rules, and its findings are warnings only.

Exit 0: nothing met the failure threshold. Exit 1: it was met. Exit 2: tfpreflight
could not run. By default only verified blocking findings exit 1. --fail-on warning
also fails on warnings, and --fail-on-partial on checks that could not complete
(PARTIAL); .tfpreflight.yml can set both as fail_on and fail_on_partial.`

const checkExample = `  # Check a saved plan
  terraform plan -out=tfplan
  tfpreflight check --plan=tfplan

  # In CI: JSON output, failing when anything could not be checked
  tfpreflight check --plan=tfplan --format=json --fail-on-partial > tfpreflight.json

  # Simulate the role that applies, not the one running the check
  tfpreflight check --plan=tfplan --principal=arn:aws:iam::123456789012:role/deploy`

func checkCommand(deps check.Dependencies) *cobra.Command {
	options := checkOptions{Format: formatText}
	command := &cobra.Command{
		Use:     "check",
		Short:   "Check a Terraform or OpenTofu plan for what would make apply fail",
		Long:    checkLong,
		Example: checkExample,
		Args:    cobra.NoArgs,
		// --update runs before the rules are chosen, so a check uses what it
		// downloads. It is best effort: a failed update keeps the rules in use
		// and never fails the check.
		PersistentPreRunE: func(command *cobra.Command, _ []string) error {
			if packDir, _ := command.Flags().GetString("pack-dir"); options.Update && packDir == "" {
				if err := runUpdate(command.Context(), command.ErrOrStderr(), indexLocation(command), "tfpreflight: "); err != nil {
					_, _ = fmt.Fprintf(command.ErrOrStderr(), "tfpreflight: warning: %v; keeping the rules in use\n", err)
				}
			}
			return useRules(command)
		},
		RunE: func(command *cobra.Command, _ []string) error {
			if options.ReportSensitive && options.ReportPath == "" {
				return toolFailure(errors.New("--report-include-sensitive requires --report <path>"))
			}
			if options.Tool == "" {
				options.Tool = os.Getenv(plan.ToolEnv)
			}
			if command.Flags().Changed("fail-on-partial") {
				enabled, _ := command.Flags().GetBool("fail-on-partial")
				options.FailOnPartial = &enabled
			}
			checked, err := check.Run(command.Context(), options.Request, deps)
			outcome := checkOutcome{Report: checked, ToolError: err}
			if err := renderCheck(command.OutOrStdout(), command.ErrOrStderr(), outcome, options); err != nil {
				return toolFailure(err)
			}
			return outcome.commandError()
		},
	}
	command.Flags().StringVar(&options.PlanPath, "plan", "", "existing saved plan file; otherwise generate a temporary plan")
	command.Flags().StringVar(&options.Tool, "tool", "", "terraform or tofu (default: "+plan.ToolEnv+", else tofu when .terraform.lock.hcl uses the OpenTofu registry, else terraform)")
	command.Flags().StringVar(&options.Principal, "principal", "", "apply IAM principal to simulate (not inspection credentials)")
	command.Flags().BoolVar(&options.Update, "update", false, "download the newest signed rules before checking (see tfpreflight update); a network failure keeps the current rules")
	command.Flags().String("index", "", "rules index for --update (default: "+packs.IndexEnv+")")
	command.Flags().StringVar(&options.ProviderVersion, "provider-version", "", "AWS provider version to check against (default: provider_version in .tfpreflight.yml, then .terraform.lock.hcl)")
	command.Flags().Var(&options.Format, "format", "output format: text or json (schema version 1)")
	command.Flags().BoolVar(&options.Details, "details", false, "show the full human-readable output: every finding's explanation, identities and coverage")
	command.Flags().BoolVar(&options.All, "all", false, "show the full human-readable output with informational findings (implies --details)")
	command.Flags().StringVar(&options.FailOn, "fail-on", "", "exit 1 on: error (default; verified blocking findings only) or warning (also any warning)")
	command.Flags().Bool("fail-on-partial", false, "also exit 1 when a check could not be completed (PARTIAL)")
	command.Flags().BoolVar(&options.Debug, "debug", false, "write runtime diagnostics to stderr")
	command.Flags().StringVar(&options.ReportPath, "report", "", "write and preview a redacted JSON support bundle at this path")
	command.Flags().BoolVar(&options.ReportSensitive, "report-include-sensitive", false, "include plan-derived text, account IDs, ARNs and resource names in the support bundle")
	return command
}

// Set accepts a format value supplied by Cobra.
func (f *renderFormat) Set(value string) error {
	format := renderFormat(value)
	if format != formatText && format != formatJSON {
		return fmt.Errorf("must be %q or %q", formatText, formatJSON)
	}
	*f = format
	return nil
}

// Type reports the name of this flag value type.
func (f *renderFormat) Type() string { return "format" }

// String returns the selected format.
func (f *renderFormat) String() string { return string(*f) }

func renderCheck(out, diagnostics io.Writer, outcome checkOutcome, options checkOptions) error {
	if options.Debug {
		for _, line := range outcome.Report.Diagnostics {
			if _, err := fmt.Fprintln(diagnostics, line); err != nil {
				return fmt.Errorf("write debug diagnostics: %w", err)
			}
		}
	}
	if options.Format == formatJSON {
		if err := report.WriteJSON(out, outcome.Report.Document(outcome.ToolError)); err != nil {
			return fmt.Errorf("write JSON report: %w", err)
		}
	} else if outcome.ToolError == nil {
		report.Render(out, outcome.Report, report.Options{All: options.All, Details: options.Details})
	}
	if options.ReportPath != "" {
		if err := writeSupportBundle(diagnostics, outcome, options); err != nil {
			return err
		}
	}
	return nil
}

func writeSupportBundle(preview io.Writer, outcome checkOutcome, options checkOptions) error {
	set, err := packs.Active()
	if err != nil {
		return fmt.Errorf("load the active rules' details for the support bundle: %w", err)
	}
	bundle := report.NewBundle(outcome.Report.Document(outcome.ToolError), Version, Commit, set.Info().ID, options.ReportSensitive)
	return report.WriteBundle(preview, options.ReportPath, bundle)
}
