// Package check runs one tfpreflight check: it reads the plan, chooses the AWS
// provider version whose rules apply, runs the checks and returns the report.
package check

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/tfpreflight/tfpreflight/internal/aws"
	"github.com/tfpreflight/tfpreflight/internal/checks/universal"
	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/internal/plan"
	"github.com/tfpreflight/tfpreflight/internal/providerversion"
	"github.com/tfpreflight/tfpreflight/internal/report"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// Request is what one run is asked to check.
type Request struct {
	// PlanPath is a saved plan; "" generates a temporary one.
	PlanPath string
	// Tool is "terraform" or "tofu" when the user chose one; "" picks by the
	// lock file.
	Tool            string
	ProviderVersion string
	// Principal is the apply identity to simulate, not the inspection
	// credentials.
	Principal string
	// FailOn is "" and FailOnPartial nil when their flags were not given.
	FailOn        string
	FailOnPartial *bool
}

// Dependencies are the tools and inspections a run uses, so tests can run the
// whole pipeline offline.
type Dependencies struct {
	Detect        func(context.Context, []plan.ToolKind) (plan.Tool, error)
	Configuration func(string) (bool, error)
	Show          func(context.Context, plan.Tool, string) ([]byte, error)
	Generate      func(context.Context, plan.Tool) (string, func(), error)
	LockPath      string
	ConfigPath    string
	AWS           func(context.Context, []model.PlannedChange, string, string, []byte) (aws.Result, error)
}

// Production is what a real run uses: the installed Terraform or OpenTofu, the
// working directory, and AWS.
func Production() Dependencies {
	return Dependencies{
		Detect:        plan.Detect,
		Configuration: plan.HasConfiguration,
		Show:          plan.ShowPlanJSON,
		Generate:      plan.GeneratePlan,
		LockPath:      providerversion.LockFile,
		ConfigPath:    providerversion.ConfigFile,
		AWS:           aws.Run,
	}
}

// Run runs one check. On error the report still holds what was gathered, which
// the CLI renders with the error.
func Run(ctx context.Context, request Request, deps Dependencies) (report.Report, error) {
	input := report.Input{}
	fail := func(err error) (report.Report, error) {
		return report.Normalize(input), err
	}
	config, policy, err := settings(request, deps.ConfigPath)
	if err != nil {
		return fail(err)
	}
	input.Policy = policy

	covered, err := packs.AWS()
	if err != nil {
		return fail(fmt.Errorf("load rules: %w", err))
	}
	input.SupportedVersions = covered

	tool, err := detectTool(ctx, request, deps)
	if err != nil {
		return fail(err)
	}
	input.ToolName, input.ToolVersion = tool.Name, tool.Version

	project, err := deps.Configuration(".")
	if err != nil {
		return fail(fmt.Errorf("inspect current directory: %w", err))
	}
	if !project {
		return fail(errors.New("no Terraform configuration found; run from a directory containing .tf files"))
	}

	planJSON, cleanup, err := loadPlan(ctx, deps, tool, request.PlanPath)
	if err != nil {
		return fail(err)
	}
	defer cleanup()

	if err := plan.ValidateDocument(planJSON); err != nil {
		return fail(fmt.Errorf("validate Terraform plan JSON: %w", err))
	}
	changes, err := plan.ParsePlan(planJSON)
	if err != nil {
		return fail(fmt.Errorf("parse Terraform resource changes: %w", err))
	}
	input.Changes = changes
	input.Providers = model.ProvidersForChanges(changes)

	var selection providerversion.Selection
	if requiresAWS(planJSON, changes) {
		if selection, err = selectProviderVersion(request, config.ProviderVersion, deps, covered, &input); err != nil {
			return fail(err)
		}
	}
	if err := runPreflightChecks(ctx, deps, request, selection, changes, planJSON, &input); err != nil {
		return fail(err)
	}
	return report.Normalize(input), nil
}

func detectTool(ctx context.Context, request Request, deps Dependencies) (plan.Tool, error) {
	tools, err := plan.ToolOrder(request.Tool, deps.LockPath)
	if err != nil {
		return plan.Tool{}, err
	}
	tool, err := deps.Detect(ctx, tools)
	if err != nil {
		return plan.Tool{}, fmt.Errorf("detect Terraform/OpenTofu: %w", err)
	}
	return tool, nil
}

// selectProviderVersion chooses the AWS provider version whose rules run and
// records it in the report input.
func selectProviderVersion(request Request, configured string, deps Dependencies, covered []string, input *report.Input) (providerversion.Selection, error) {
	lock, lockErr := plan.AWSProviderVersion(deps.LockPath)
	chosen, err := providerversion.Choose(request.ProviderVersion, configured, lock, lockErr)
	if err != nil {
		return providerversion.Selection{}, err
	}
	selection, err := chosen.Resolve(covered)
	if err != nil {
		return providerversion.Selection{}, err
	}
	input.ProviderVersion = selection.Version
	input.Selection = report.ProviderSelection{
		Mode: string(selection.Mode), RulesVersion: selection.RulesVersion,
		Source: string(selection.Source), LockVersion: selection.LockVersion, Summary: selection.Summary(),
	}
	return selection, nil
}

// runPreflightChecks runs the universal checks, then the AWS checks. Universal
// findings are recorded first, so a failed AWS run still reports them.
func runPreflightChecks(ctx context.Context, deps Dependencies, request Request, selection providerversion.Selection, changes []model.PlannedChange, planJSON []byte, input *report.Input) error {
	input.Findings = universal.Run(changes)

	awsResult, err := deps.AWS(ctx, changes, request.Principal, selection.RulesVersion, planJSON)
	if err != nil {
		return fmt.Errorf("run AWS preflight checks: %w", err)
	}
	input.Findings = append(input.Findings, awsResult.Findings...)
	if selection.Version != "" {
		input.Findings = applySelection(selection, input.Findings)
	}
	input.AWSContext = awsResult.Context
	input.Coverage = awsResult.Coverage
	input.Diagnostics = awsResult.Debug
	return nil
}

func loadPlan(ctx context.Context, deps Dependencies, tool plan.Tool, path string) ([]byte, func(), error) {
	cleanup := func() {}
	if path != "" {
		if err := plan.ValidatePlanFile(path); err != nil {
			return nil, cleanup, fmt.Errorf("validate plan path: %w", err)
		}
	} else {
		var err error
		if path, cleanup, err = generatePlan(ctx, deps, tool); err != nil {
			return nil, cleanup, err
		}
	}
	planJSON, err := deps.Show(ctx, tool, path)
	if err != nil {
		cleanup()
		return nil, func() {}, fmt.Errorf("show Terraform plan as JSON: %w", err)
	}
	return planJSON, cleanup, nil
}

func generatePlan(ctx context.Context, deps Dependencies, tool plan.Tool) (string, func(), error) {
	path, cleanup, err := deps.Generate(ctx, tool)
	var failed *plan.CommandError
	switch {
	case errors.As(err, &failed):
		return "", cleanup, fmt.Errorf("generate Terraform plan: %w\n\n%s", err, savedPlanHint(tool.Kind))
	case err != nil:
		return "", cleanup, fmt.Errorf("generate Terraform plan: %w", err)
	}
	return path, cleanup, nil
}

// savedPlanHint is what to do when the plan tfpreflight runs fails, usually
// for want of the credentials or settings the plan needs.
func savedPlanHint(kind plan.ToolKind) string {
	command := "terraform"
	if kind == plan.OpenTofu {
		command = "tofu"
	}
	return "If the plan needs credentials or settings that are not available here, save a plan where they are and pass it in:\n" +
		"  " + command + " plan -out=tfplan\n" +
		"  tfpreflight check --plan=tfplan"
}

func requiresAWS(data []byte, changes []model.PlannedChange) bool {
	for _, provider := range model.ProvidersForChanges(changes) {
		if provider == model.ProviderAWS {
			return true
		}
	}
	var document struct {
		Configuration struct {
			Providers map[string]struct {
				FullName string `json:"full_name"`
			} `json:"provider_config"`
		} `json:"configuration"`
	}
	// The plan was validated already; a provider block that does not decode just
	// does not count.
	_ = json.Unmarshal(data, &document)
	for _, provider := range document.Configuration.Providers {
		if model.NormalizeProvider(provider.FullName) == model.ProviderAWS {
			return true
		}
	}
	return false
}

// applySelection makes the findings say what the version choice means. Rules
// were never built for a version the packs do not cover exactly, so there no
// finding may block: each error becomes a warning. A version other than the lock
// file's adds a warning of its own.
func applySelection(selection providerversion.Selection, findings []model.Finding) []model.Finding {
	out := make([]model.Finding, 0, len(findings)+1)
	for _, finding := range findings {
		if !selection.Blocking() && finding.Severity == model.SeverityError {
			finding.Severity = model.SeverityWarning
			finding.Notes = append(append([]string(nil), finding.Notes...), fmt.Sprintf(
				"Reported as a warning: AWS provider %s is %s, so these are %s rules and cannot block.", selection.Version, selection.Mode, selection.RulesVersion))
		}
		out = append(out, finding)
	}
	if selection.Mismatch() {
		out = append(out, model.Finding{
			ID: "provider-version-mismatch", Provider: "aws", Category: "configuration",
			Severity: model.SeverityWarning, Confidence: model.ConfidenceHigh,
			Title:       fmt.Sprintf("These results describe AWS provider %s, but the project runs %s", selection.Version, selection.LockVersion),
			Problem:     fmt.Sprintf("The version came from %s; .terraform.lock.hcl selects %s. Findings for %s may not hold for %s.", providerversion.DescribeSource(selection.Source), selection.LockVersion, selection.Version, selection.LockVersion),
			Remediation: "Check against the version the lock file selects, or update the lock file.",
			Brief:       fmt.Sprintf("These results are for AWS provider %s, but .terraform.lock.hcl selects %s.", selection.Version, selection.LockVersion),
			Next:        fmt.Sprintf("Fix: check against %s, or update the lock file.", selection.LockVersion),
		})
	}
	return out
}

func settings(request Request, path string) (providerversion.Config, report.Policy, error) {
	config, err := providerversion.ReadConfig(path)
	if err != nil {
		return config, report.Policy{}, err
	}
	policy, err := failurePolicy(request, config)
	return config, policy, err
}

// failurePolicy is when the run exits 1: each setting from its flag, else the
// configuration file, else the default.
func failurePolicy(request Request, config providerversion.Config) (report.Policy, error) {
	policy := report.DefaultPolicy
	var sources []string
	switch {
	case request.FailOn != "":
		if request.FailOn != report.FailOnError && request.FailOn != report.FailOnWarning {
			return report.Policy{}, fmt.Errorf("--fail-on must be %q or %q, not %q", report.FailOnError, report.FailOnWarning, request.FailOn)
		}
		policy.FailOn = request.FailOn
		sources = append(sources, "--fail-on")
	case config.FailOn != "":
		policy.FailOn = config.FailOn
		sources = append(sources, providerversion.ConfigFile)
	}
	switch {
	case request.FailOnPartial != nil:
		policy.FailOnPartial = *request.FailOnPartial
		sources = append(sources, "--fail-on-partial")
	case config.FailOnPartial != nil:
		policy.FailOnPartial = *config.FailOnPartial
		if len(sources) == 0 || sources[len(sources)-1] != providerversion.ConfigFile {
			sources = append(sources, providerversion.ConfigFile)
		}
	}
	if len(sources) > 0 {
		policy.Source = strings.Join(sources, ", ")
	}
	return policy, nil
}
