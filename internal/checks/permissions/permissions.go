// Package permissions predicts IAM denials by simulating each planned
// operation's permission for the apply identity. What it cannot simulate is
// reported as incomplete coverage, never as a pass.
package permissions

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

type iamSimulator interface {
	SimulatePrincipalPolicy(context.Context, *iam.SimulatePrincipalPolicyInput, ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error)
	GetContextKeysForPrincipalPolicy(context.Context, *iam.GetContextKeysForPrincipalPolicyInput, ...func(*iam.Options)) (*iam.GetContextKeysForPrincipalPolicyOutput, error)
}

type plannedPermission struct {
	change         model.PlannedChange
	resourceLabel  string
	operationLabel string
	operation      packs.OperationRule
	attributes     []string
	// siblings are the other operations of the same action; they say which
	// service the resource belongs to.
	siblings []packs.OperationRule
}

// Result is what the permission check found.
type Result struct {
	Findings []model.Finding
	// Unchecked are resources whose permissions could not be simulated at all.
	Unchecked Unchecked
	// Partial are resources with a permission that may be denied but cannot be
	// said to be, because the resource or the request context was not fully
	// known.
	Partial Unchecked
	// Answered counts the permissions IAM gave a decision for.
	Answered int
}

// PredictPermissions simulates principal's permissions for the planned changes.
// config's credentials authorize the simulation; principal is the identity
// simulated.
func PredictPermissions(ctx context.Context, config awssdk.Config, principal string, scope Scope, rules []packs.ResolvedRule) Result {
	requirements := requiredPermissions(rules)
	if len(requirements) == 0 {
		return Result{}
	}
	return simulatePermissions(ctx, iam.NewFromConfig(config), principal, scope, requirements)
}

// Unchecked maps each resource whose permissions could not be simulated to the
// reason. It is partial coverage, never a failed run: being unable to ask IAM
// says nothing about the apply.
type Unchecked map[string]string

func requiredPermissions(rules []packs.ResolvedRule) []plannedPermission {
	var requirements []plannedPermission
	for _, rule := range rules {
		for _, operation := range rule.Action.Operations {
			// Unknown certainty is still checked, at generated trust; a
			// conditional operation only when the plan proves its condition.
			if operation.Required(rule.Change) {
				requirements = append(requirements, plannedPermission{
					change: rule.Change, resourceLabel: rule.ResourceLabel, operationLabel: rule.Action.OperationLabel, operation: operation,
					attributes: rule.Attributes, siblings: rule.Action.Operations,
				})
			}
		}
	}
	return requirements
}

// AWS documents no limit on the actions one simulation names; 100 keeps requests
// small, and results are read page by page.
const (
	actionsPerSimulation = 100
	simulationPageSize   = 1000
	simulationWorkers    = 8
)

// batch is one SimulatePrincipalPolicy call: every distinct action against one
// resource and request context.
type batch struct {
	target  target
	keys    []contextKey
	actions []string
	// decisions is each action's result, keyed by the lower-cased action; err is
	// set when the call failed or was never made.
	decisions map[string]types.EvaluationResult
}

func simulatePermissions(ctx context.Context, client iamSimulator, principal string, scope Scope, requirements []plannedPermission) Result {
	var simulation Result
	known := loadActions()
	// The condition keys the principal's policies test, asked for only when a
	// denial may rest on a value tfpreflight inferred.
	var policyKeys map[string]bool
	asked := false
	keysOf := func() map[string]bool {
		if !asked {
			policyKeys, asked = principalContextKeys(ctx, client, principal), true
		}
		return policyKeys
	}
	batches, of := batchRequirements(requirements, scope, known)
	failure := runBatches(ctx, client, principal, batches)
	for index, requirement := range requirements {
		b := batches[of[index]]
		evaluation, decided := b.decisions[strings.ToLower(requirement.operation.Permission)]
		if !decided {
			// Simulation stops at the first failure: denial, throttling or a
			// dead network fails every later call too. Decided results are kept;
			// every undecided resource is partial, with the failure's reason.
			if simulation.Unchecked == nil {
				simulation.Unchecked = Unchecked{}
			}
			if failure == "" {
				failure = uncheckedReason(requirement.operation.Permission, errors.New("no decision returned"))
			}
			simulation.Unchecked[requirement.change.Address] = failure
			continue
		}
		simulation.Answered++
		switch evaluation.EvalDecision {
		case types.PolicyEvaluationDecisionTypeExplicitDeny:
			simulation.Findings = append(simulation.Findings, explicitDenyFinding(ctx, client, principal, requirement, b, evaluation, keysOf))
		case types.PolicyEvaluationDecisionTypeImplicitDeny:
			if reason := uncertainDenial(evaluation.MissingContextValues, b.target, b.keys, keysOf); reason != "" {
				simulation.partial(requirement, reason)
				continue
			}
			simulation.Findings = append(simulation.Findings, implicitDenyFinding(ctx, client, principal, requirement, b))
		}
	}
	return simulation
}

// implicitDenyFinding reports a decided implicit deny, blocking only when
// nothing outside the simulation could allow the call.
func implicitDenyFinding(ctx context.Context, client iamSimulator, principal string, requirement plannedPermission, b *batch) model.Finding {
	finding := permissionDeniedFinding(requirement, principal, string(types.PolicyEvaluationDecisionTypeImplicitDeny), b.target.ARN)
	if requirement.operation.Trust == "generated" {
		markGenerated(&finding)
	}
	// The simulation reads no resource-based policy, so an implicit deny blocks
	// only when no such policy could allow the call.
	if reason := resourcePolicyMayAllow(requirement, b.target); finding.Severity == model.SeverityError && reason != "" {
		demote(&finding, reason, "Check: a resource policy, such as a bucket or key policy, could still allow it.")
	}
	if finding.Severity == model.SeverityError {
		demoteIfOnlyBuiltARN(ctx, client, principal, requirement, b, &finding)
	}
	return finding
}

// explicitDenyFinding reports an explicit deny. It is never partial: no allow,
// for this resource or any other, overrides it, so it holds against "*" and
// for generated rules too. It blocks only when IAM had every context value it
// needed and the rule says the provider always makes the call; otherwise it
// is a warning that says why.
func explicitDenyFinding(ctx context.Context, client iamSimulator, principal string, requirement plannedPermission, b *batch, evaluation types.EvaluationResult, policyKeysOf func() map[string]bool) model.Finding {
	finding := permissionDeniedFinding(requirement, principal, string(types.PolicyEvaluationDecisionTypeExplicitDeny), b.target.ARN)
	finding.Next = "Fix: remove or narrow the deny " + denySource(evaluation, principal) + "."
	if reason, check := explicitDenyDoubt(requirement.operation, evaluation.MissingContextValues, b.keys, policyKeysOf); reason != "" {
		demote(&finding, reason, check)
		finding.Explanation = "A policy explicitly denies this action, so Terraform apply may fail when it makes this call."
		return finding
	}
	demoteIfOnlyBuiltARN(ctx, client, principal, requirement, b, &finding)
	return finding
}

// explicitDenyDoubt says why an explicit deny may not stop the apply, as a note
// and as the short "Check:" line, or "" when nothing does.
func explicitDenyDoubt(operation packs.OperationRule, missing []string, keys []contextKey, policyKeysOf func() map[string]bool) (note, check string) {
	switch {
	case len(missing) > 0:
		return "Reported as a warning: IAM needed request context the plan does not give (" + strings.Join(missing, ", ") + "), so the deny may not apply to the real request.",
			"Check: the deny depends on request details the plan does not give (" + strings.Join(missing, ", ") + ")."
	case operation.Certainty == packs.CertaintyConditional:
		return "Reported as a warning: the provider makes this call only in some cases, so the apply may not make it.",
			"Check: the provider makes this call only in some cases."
	case !operation.AlwaysRuns():
		return "Reported as a warning: the rule does not say whether the provider always makes this call.",
			"Check: the rules do not say whether the provider always makes this call."
	}
	if key, ok := guessedKeyTested(keys, policyKeysOf); ok {
		return "Reported as a warning: the policy tests " + key.Name + ", whose value (" + strings.Join(key.Values, ", ") + ") tfpreflight inferred.",
			"Check: the deny depends on " + key.Name + ", whose value tfpreflight inferred."
	}
	return "", ""
}

// denySource is where IAM says an explicit deny sits, as the "Fix:" line names
// it: the organization's service control policies, the principal's permissions
// boundary, or else the principal's own policies.
func denySource(evaluation types.EvaluationResult, principal string) string {
	if detail := evaluation.OrganizationsDecisionDetail; detail != nil && !detail.AllowedByOrganizations {
		return "in your organization's service control policies"
	}
	if detail := evaluation.PermissionsBoundaryDecisionDetail; detail != nil && !detail.AllowedByPermissionsBoundary {
		return "in the permissions boundary of " + principalLabel(principal)
	}
	return "on " + principalLabel(principal)
}

// demoteIfOnlyBuiltARN keeps a denial from blocking when IAM denies it only on
// the ARN tfpreflight built and not against "*": no block may rest on that ARN.
func demoteIfOnlyBuiltARN(ctx context.Context, client iamSimulator, principal string, requirement plannedPermission, b *batch, finding *model.Finding) {
	if b.target.ARN != "*" && !deniedEverywhere(ctx, client, principal, requirement, b.keys) {
		demote(finding, "IAM allows this action against every resource (\"*\") but denies it for this resource's ARN; reported as a warning, since the ARN was built by tfpreflight.",
			"Check: IAM denies it only for the resource ARN tfpreflight built, not for every resource.")
	}
}

// batchRequirements groups requirements into simulations: one per resource ARN
// and request context, at most actionsPerSimulation actions each. of[i] is the
// batch that decides requirements[i].
func batchRequirements(requirements []plannedPermission, scope Scope, known map[string]iamAction) ([]*batch, []int) {
	var batches []*batch
	open := map[string]int{}
	of := make([]int, len(requirements))
	for index, requirement := range requirements {
		target := targetFor(requirement, scope, known)
		keys := contextFor(requirement, scope, known)
		group := groupKey(target, keys)
		position, found := open[group]
		action := requirement.operation.Permission
		if !found || !joinBatch(batches[position], action) {
			position = len(batches)
			open[group] = position
			batches = append(batches, &batch{target: target, keys: keys, actions: []string{action}})
		}
		of[index] = position
	}
	return batches, of
}

// joinBatch adds action to an open batch, or reports false when the batch is
// full.
func joinBatch(b *batch, action string) bool {
	if containsFold(b.actions, action) {
		return true
	}
	if len(b.actions) == actionsPerSimulation {
		return false
	}
	b.actions = append(b.actions, action)
	return true
}

func groupKey(target target, keys []contextKey) string {
	var key strings.Builder
	key.WriteString(target.ARN)
	for _, entry := range keys {
		key.WriteString("\x00" + entry.Name + "=" + strings.Join(entry.Values, "\x01"))
	}
	return key.String()
}

func containsFold(values []string, value string) bool {
	for _, existing := range values {
		if strings.EqualFold(existing, value) {
			return true
		}
	}
	return false
}

// runBatches simulates every batch and returns the reason for any left
// undecided. The first goes alone, so a principal IAM will not simulate, or a
// dead network, costs one call; the rest run simulationWorkers at a time, and
// the first failure stops new calls.
func runBatches(ctx context.Context, client iamSimulator, principal string, batches []*batch) string {
	if len(batches) == 0 {
		return ""
	}
	if err := simulateBatch(ctx, client, principal, batches[0]); err != nil {
		return uncheckedReason(batches[0].actions[0], err)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	run := &batchRun{cancel: cancel}
	var wg sync.WaitGroup
	work := make(chan *batch)
	for worker := 0; worker < simulationWorkers && worker < len(batches)-1; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			run.drain(ctx, client, principal, work)
		}()
	}
	for _, b := range batches[1:] {
		work <- b
	}
	close(work)
	wg.Wait()
	return run.failure
}

// batchRun is the workers' shared state: the first failure, which cancels the
// rest.
type batchRun struct {
	mu      sync.Mutex
	failure string
	cancel  context.CancelFunc
}

func (r *batchRun) drain(ctx context.Context, client iamSimulator, principal string, work <-chan *batch) {
	for b := range work {
		if r.stopped() {
			continue
		}
		if err := simulateBatch(ctx, client, principal, b); err != nil {
			r.fail(b, err)
		}
	}
}

func (r *batchRun) stopped() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failure != ""
}

func (r *batchRun) fail(b *batch, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failure == "" {
		r.failure = uncheckedReason(b.actions[0], err)
		r.cancel()
	}
}

// simulateBatch makes one simulation, reading every page of its results.
func simulateBatch(ctx context.Context, client iamSimulator, principal string, b *batch) error {
	b.decisions = map[string]types.EvaluationResult{}
	var marker *string
	for {
		output, err := client.SimulatePrincipalPolicy(ctx, &iam.SimulatePrincipalPolicyInput{
			PolicySourceArn: &principal,
			ActionNames:     b.actions,
			ResourceArns:    []string{b.target.ARN},
			ContextEntries:  contextEntries(b.keys),
			MaxItems:        awssdk.Int32(simulationPageSize),
			Marker:          marker,
		})
		if err == nil && len(output.EvaluationResults) == 0 {
			err = errors.New("no decision returned")
		}
		if err != nil {
			return err
		}
		for _, evaluation := range output.EvaluationResults {
			if evaluation.EvalActionName == nil {
				if len(b.actions) == 1 {
					b.decisions[strings.ToLower(b.actions[0])] = evaluation
				}
				continue
			}
			b.decisions[strings.ToLower(*evaluation.EvalActionName)] = evaluation
		}
		if !output.IsTruncated || output.Marker == nil {
			return nil
		}
		marker = output.Marker
	}
}

func deniedEverywhere(ctx context.Context, client iamSimulator, principal string, requirement plannedPermission, keys []contextKey) bool {
	output, err := client.SimulatePrincipalPolicy(ctx, &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: &principal, ActionNames: []string{requirement.operation.Permission},
		ResourceArns: []string{"*"}, ContextEntries: contextEntries(keys),
	})
	if err != nil || len(output.EvaluationResults) == 0 {
		return false
	}
	decision := output.EvaluationResults[0].EvalDecision
	return decision == types.PolicyEvaluationDecisionTypeImplicitDeny || decision == types.PolicyEvaluationDecisionTypeExplicitDeny
}

// uncertainDenial says why a denial cannot be reported as certain, or "".
func uncertainDenial(missing []string, target target, keys []contextKey, policyKeysOf func() map[string]bool) string {
	if len(missing) > 0 {
		return "may be denied: the policy depends on request context the plan does not give (" + strings.Join(missing, ", ") + ")"
	}
	if !target.Exact {
		return `may be denied: simulated against every resource ("*") because ` + target.Reason + "; the policy might allow this resource specifically"
	}
	if key, ok := guessedKeyTested(keys, policyKeysOf); ok {
		return "may be denied: the policy tests " + key.Name + ", whose value (" + strings.Join(key.Values, ", ") + ") tfpreflight inferred"
	}
	return ""
}

// guessedKeyTested finds a context value tfpreflight inferred that the
// principal's policies test: a denial may rest on the inference.
func guessedKeyTested(keys []contextKey, policyKeysOf func() map[string]bool) (contextKey, bool) {
	for _, key := range keys {
		if !key.Guessed {
			continue
		}
		if policyKeys := policyKeysOf(); policyKeys == nil || policyKeys[strings.ToLower(key.Name)] {
			return key, true
		}
	}
	return contextKey{}, false
}

func (r *Result) partial(requirement plannedPermission, reason string) {
	if r.Partial == nil {
		r.Partial = Unchecked{}
	}
	if previous, ok := r.Partial[requirement.change.Address]; ok {
		reason = previous + "; " + requirement.operation.Permission + " " + reason
	} else {
		reason = requirement.operation.Permission + " " + reason
	}
	r.Partial[requirement.change.Address] = reason
}

// principalContextKeys is every condition key the principal's policies test, or
// nil when IAM cannot say.
func principalContextKeys(ctx context.Context, client iamSimulator, principal string) map[string]bool {
	output, err := client.GetContextKeysForPrincipalPolicy(ctx, &iam.GetContextKeysForPrincipalPolicyInput{PolicySourceArn: &principal})
	if err != nil || output == nil {
		return nil
	}
	keys := map[string]bool{}
	for _, name := range output.ContextKeyNames {
		keys[strings.ToLower(name)] = true
	}
	return keys
}

func contextEntries(keys []contextKey) []types.ContextEntry {
	entries := make([]types.ContextEntry, 0, len(keys))
	for _, key := range keys {
		kind := types.ContextKeyTypeEnumString
		if key.Type == "stringList" {
			kind = types.ContextKeyTypeEnumStringList
		}
		entries = append(entries, types.ContextEntry{ContextKeyName: awssdk.String(key.Name), ContextKeyType: kind, ContextKeyValues: key.Values})
	}
	return entries
}

// PartialFindings reports each resource whose permission may be denied.
func PartialFindings(partial Unchecked) []model.Finding {
	findings := make([]model.Finding, 0, len(partial))
	for address, reason := range partial {
		findings = append(findings, model.Finding{
			ID: "aws.permission-may-be-denied", Provider: "aws", Resource: address, Category: "permission",
			Severity: model.SeverityInfo, Confidence: model.ConfidenceLow,
			Title:       "Apply permission may be denied",
			Explanation: "IAM did not allow this when simulated, but the simulation could not use the exact resource or request context, so the policy may still allow it.",
			Notes:       []string{reason},
			Brief:       "IAM did not clearly allow " + strings.Join(actionsIn(reason), ", ") + " for the apply identity.",
			Next:        "Check: the exact resource or request was not known, so a policy may still allow it.",
		})
	}
	return findings
}

// partialAction matches each action a partial reason names: every reason
// uncertainDenial gives starts "may be denied", after the action.
var partialAction = regexp.MustCompile(`([a-z0-9-]+:[A-Za-z0-9*]+) may be denied`)

func actionsIn(reason string) []string {
	var actions []string
	for _, match := range partialAction.FindAllStringSubmatch(reason, -1) {
		actions = append(actions, match[1])
	}
	return actions
}

func uncheckedReason(permission string, err error) string {
	return fmt.Sprintf("permission simulation unavailable: simulating %s failed: %v", permission, err)
}

// UncheckedFindings reports each resource whose permissions were not simulated.
// They are informational: nothing is known to be wrong.
func UncheckedFindings(unchecked Unchecked) []model.Finding {
	findings := make([]model.Finding, 0, len(unchecked))
	for address, reason := range unchecked {
		findings = append(findings, model.Finding{
			ID: "aws.permission-simulation-unavailable", Provider: "aws", Resource: address, Category: "permission",
			Severity: model.SeverityInfo, Confidence: model.ConfidenceLow,
			Title:       "Apply permissions could not be checked",
			Explanation: "IAM could not simulate the apply identity's permissions, so they were not checked. This is not a finding against the plan.",
			Notes:       []string{reason},
			AWSError:    reason,
			Brief:       "Could not ask IAM whether the apply identity may run this resource's actions.",
			Next:        "Check: the inspection identity needs iam:SimulatePrincipalPolicy, and AWS must be reachable.",
		})
	}
	return findings
}

// permissionDeniedFinding is a blocking denial; callers demote it when it may
// not hold.
func permissionDeniedFinding(requirement plannedPermission, principal, decision, resource string) model.Finding {
	remediation := fmt.Sprintf("Allow %s for the deployment identity.", requirement.operation.Permission)
	// An allow cannot override an explicit deny.
	if decision == string(types.PolicyEvaluationDecisionTypeExplicitDeny) {
		remediation = fmt.Sprintf("Remove or narrow the policy statement that denies %s to the deployment identity.", requirement.operation.Permission)
	}
	return model.Finding{
		ID:                  "aws.permission-denied",
		Provider:            "aws",
		Resource:            requirement.change.Address,
		Category:            "permission",
		Severity:            model.SeverityError,
		Confidence:          model.ConfidenceHigh,
		Title:               "Apply will likely fail",
		Operation:           operationDescription(requirement),
		Problem:             fmt.Sprintf("The deployment %s does not have %s.", principalKind(principal), requirement.operation.Permission),
		Permission:          requirement.operation.Permission,
		Principal:           principal,
		Decision:            decision,
		DecisionExplanation: decisionExplanation(decision),
		Explanation:         "Terraform can generate this plan, but AWS will reject this action during terraform apply.",
		Remediation:         remediation,
		Notes:               []string{"Simulated against " + resource + "; AWS decision: " + decision + "."},
		Brief:               fmt.Sprintf("The apply %s is not allowed to run %s.", principalKind(principal), requirement.operation.Permission),
		Next:                fmt.Sprintf("Fix: allow %s for %s.", requirement.operation.Permission, principalLabel(principal)),
	}
}

// markGenerated makes an implicit deny a warning when its operation rule is
// generated and unverified.
func markGenerated(finding *model.Finding) {
	finding.Severity, finding.Confidence = model.SeverityWarning, model.ConfidenceMedium
	finding.Title = "Potential apply permission failure"
	finding.Explanation = "Terraform apply may fail when it attempts this action. This rule was generated from Terraform provider behavior and has not yet been independently verified."
	mayNotBeAllowed(finding, "Check: this rule comes from the provider's source and is not yet verified against AWS.")
}

// demote keeps a denial from blocking, with why, and the short check that says
// it.
func demote(finding *model.Finding, why, check string) {
	finding.Severity, finding.Confidence = model.SeverityWarning, model.ConfidenceMedium
	finding.Title = "Potential apply permission failure"
	finding.Notes = append(finding.Notes, why)
	mayNotBeAllowed(finding, check)
}

func mayNotBeAllowed(finding *model.Finding, check string) {
	finding.Brief = fmt.Sprintf("The apply %s may not be allowed to run %s.", principalKind(finding.Principal), finding.Permission)
	finding.Next = check
}

// principalKind is what the apply principal is, in a word: role, user, or
// identity when its ARN does not say.
func principalKind(principal string) string {
	kind, _ := principalName(principal)
	return kind
}

// principalLabel names the apply principal without its ARN or account:
// role "deploy", user "ci", or the apply identity.
func principalLabel(principal string) string {
	kind, name := principalName(principal)
	if name == "" {
		return "the apply identity"
	}
	return fmt.Sprintf("%s %q", kind, name)
}

// principalName is a principal ARN's kind and name: an assumed-role session is
// its role, and a role or user name drops its path.
func principalName(principal string) (kind, name string) {
	_, resource, found := strings.Cut(principal, ":assumed-role/")
	if found {
		name, _, _ = strings.Cut(resource, "/")
		return "role", name
	}
	for _, kind := range []string{"role", "user"} {
		if _, resource, found := strings.Cut(principal, ":"+kind+"/"); found {
			return kind, resource[strings.LastIndex(resource, "/")+1:]
		}
	}
	return "identity", ""
}

// operationDescription is what Terraform is doing, in words: "Create an IAM
// role". Generated rules label a resource by its type, which is named in prose.
func operationDescription(requirement plannedPermission) string {
	label := requirement.resourceLabel
	if strings.HasPrefix(label, "aws_") {
		label = model.ResourceName(label)
	}
	return requirement.operationLabel + " " + model.WithArticle(label)
}

func decisionExplanation(decision string) string {
	switch decision {
	case string(types.PolicyEvaluationDecisionTypeImplicitDeny):
		return "No policy currently allows this action."
	case string(types.PolicyEvaluationDecisionTypeExplicitDeny):
		return "A policy explicitly blocks this action."
	default:
		return "AWS did not allow this action."
	}
}
