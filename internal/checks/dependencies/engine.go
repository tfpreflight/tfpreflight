package dependencies

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

// ExistenceResolver asks AWS whether one identifier exists. Exists means the
// response contains the object; NotFound means the lookup's own not-found code
// or type. Anything else is Unknown, including AccessDenied, throttling, and a
// successful but empty answer: ECS DescribeClusters, for one, lists missing
// clusters under failures.
type ExistenceResolver interface {
	Exists(ctx context.Context, lookup Lookup, scope Scope, identifier string) (Existence, string)
}

// Scope is the account and region a lookup runs in. The same identifier names a
// different object elsewhere, so answers are shared only within one scope.
type Scope struct {
	Region  string
	Account string
}

// Key identifies the question a lookup asks, for caching and deduplication.
func (s Scope) Key() string { return s.Account + "|" + s.Region }

// LookupRequest is one question the engine is about to ask AWS.
type LookupRequest struct {
	Lookup     Lookup
	Scope      Scope
	Identifier string
}

// Prefetcher resolves lookups in batches before evaluation. It only saves time:
// evaluation still asks for every identifier, in a fixed order, so the verdicts
// are the same without it.
type Prefetcher interface {
	Prefetch(ctx context.Context, requests []LookupRequest)
}

// Engine evaluates dependency rules against a plan.
type Engine struct {
	Existence []ExistenceRule
	Resolver  ExistenceResolver
	// Scope is where every lookup runs. A resource that needs another scope is
	// answered without asking AWS.
	Scope Scope
	// Enforcement is what AWS was observed to do when a target was absent. Only
	// it can make a dependency finding blocking.
	Enforcement *EnforcementKnowledge
	// ProviderVersion selects the enforcement evidence recorded for that
	// version.
	ProviderVersion string
}

// Evaluate applies every rule to every relevant planned change. Lookups are
// resolved together first, then evaluation runs in address order, so the results
// do not depend on which answer arrived first.
func (e Engine) Evaluate(ctx context.Context, plan Plan) ([]Result, map[string]string) {
	if prefetcher, ok := e.Resolver.(Prefetcher); ok {
		prefetcher.Prefetch(ctx, e.pendingLookups(ctx, plan))
	}
	return e.evaluate(ctx, plan)
}

// pendingLookups runs the evaluation against a resolver that answers nothing, to
// learn which lookups it needs before sending any. What is decided without AWS
// never reaches the list.
func (e Engine) pendingLookups(ctx context.Context, plan Plan) []LookupRequest {
	collector := &lookupCollector{seen: map[string]bool{}}
	dry := e
	dry.Resolver = collector
	dry.evaluate(ctx, plan)
	return collector.requests
}

type lookupCollector struct {
	seen     map[string]bool
	requests []LookupRequest
}

// Exists returns the collected answer for one dependency lookup.
func (c *lookupCollector) Exists(_ context.Context, lookup Lookup, scope Scope, identifier string) (Existence, string) {
	request := LookupRequest{Lookup: lookup, Scope: scope, Identifier: identifier}
	key := scope.Key() + "\x00" + lookup.Service + "/" + lookup.Operation + "/" + lookup.Field + "\x00" + identifier
	if !c.seen[key] {
		c.seen[key] = true
		c.requests = append(c.requests, request)
	}
	// Exists keeps the walk going, so every identifier is collected.
	return Exists, "collecting"
}

func (e Engine) evaluate(ctx context.Context, plan Plan) ([]Result, map[string]string) {
	var results []Result
	coverage := map[string]string{}
	addresses := make([]string, 0, len(plan.Changes))
	for address := range plan.Changes {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)

	for _, address := range addresses {
		change := plan.Changes[address]
		creates, deletes := hasAction(change.Actions, "create"), hasAction(change.Actions, "delete")
		if !creates && !deletes {
			coverage[address] = CoverageNotRequested
			continue
		}
		var changeResults []Result
		if creates {
			changeResults = e.existenceResults(ctx, plan, change)
		}
		results = append(results, changeResults...)
		coverage[address] = dependencyCoverage(changeResults)
	}
	return results, coverage
}

func (e Engine) existenceResults(ctx context.Context, plan Plan, change PlannedValues) []Result {
	var results []Result
	for _, rule := range e.Existence {
		if rule.Resource == change.ResourceType {
			results = append(results, e.existence(ctx, plan, change, rule))
		}
	}
	return results
}

func dependencyCoverage(results []Result) string {
	applied, partial := 0, false
	for _, outcome := range results {
		if outcome.Verdict != VerdictNotApplicable {
			applied++
		}
		partial = partial || outcome.Verdict == VerdictPartial
	}
	switch {
	case applied == 0:
		// No rule is modelled for this resource, which may still have
		// dependencies.
		return CoverageNoRule
	case partial:
		return CoveragePartial
	default:
		return CoverageChecked
	}
}

func (e Engine) existence(ctx context.Context, plan Plan, change PlannedValues, rule ExistenceRule) Result {
	outcome := Result{Address: change.Address, Family: FamilyExistence}
	reference, recorded := plan.References[change.Address][rule.Attribute]
	if !recorded {
		return unrecorded(plan, change, rule, outcome)
	}

	var identifiers []string
	if reference.Origin == OriginSamePlan {
		external, decided, done := samePlanTargets(plan, change, rule, reference, outcome)
		if done {
			return decided
		}
		identifiers = external
	}

	if reason := unreachableTarget(plan, change, rule, reference); reason != "" {
		return outcome.partial(reason)
	}

	if identifiers == nil {
		known, complete := knownIdentifiers(change.Route(rule.Route()))
		if !complete || len(known) == 0 {
			return outcome.partial(rule.Attribute + " is not known until apply")
		}
		identifiers = known
	}
	if reason := hiddenProducer(plan, change, rule, reference, identifiers); reason != "" {
		return outcome.partial(reason)
	}
	if e.Resolver == nil {
		return outcome.partial("no inspector is available for " + rule.Lookup.Service)
	}

	return e.inspectTargets(ctx, plan, change, rule, identifiers, outcome)
}

func (r Result) partial(reason string) Result {
	r.Verdict, r.Reason = VerdictPartial, reason
	return r
}

func unrecorded(plan Plan, change PlannedValues, rule ExistenceRule, outcome Result) Result {
	if _, known := plan.References[change.Address]; !known {
		return outcome.partial("resource configuration expressions unavailable")
	}
	outcome.Verdict, outcome.Reason = VerdictNotApplicable, rule.Attribute+" is not set in configuration"
	return outcome
}

// unreachableTarget says why a lookup cannot answer for this reference, or "".
// Lookups run in the default provider's account and region; a target reached
// through another provider, or moved by a scope argument, is not there, so its
// absence proves nothing.
func unreachableTarget(plan Plan, change PlannedValues, rule ExistenceRule, reference AttributeReference) string {
	for _, scope := range rule.ScopeAttributes {
		if _, set := plan.References[change.Address][scope]; set {
			return scope + " is set, so the target may be in another account or region"
		}
	}
	if plan.Providers[change.Address] != DefaultProvider {
		return model.AliasedProviderReason
	}
	if _, set := plan.References[change.Address]["region"]; set {
		return "resource-level region override requires a separate inspection context"
	}
	if reference.Origin == OriginLocal || reference.Origin == OriginModuleOutput || reference.Origin == OriginUnknown {
		return "dependency expression provenance is unresolved: " + reference.Origin
	}
	if reference.Origin == OriginVariable && strings.HasPrefix(change.Address, "module.") && !reference.ExternalModuleInput {
		return "module input may reference a parent-plan producer; input provenance is unresolved"
	}
	return ""
}

// hiddenProducer says why this plan may produce an identifier without recording
// it, or "". A local, a module output or each.value can carry a planned target's
// value with no recorded reference.
func hiddenProducer(plan Plan, change PlannedValues, rule ExistenceRule, reference AttributeReference, identifiers []string) string {
	if reference.Origin == OriginLiteral || reference.Origin == OriginVariable || reference.Origin == OriginDataSource {
		return ""
	}
	created := plannedValues(plan, func(address string) bool {
		planned := plan.Changes[address]
		return address != change.Address && planned.ResourceType == rule.TargetResource && hasAction(planned.Actions, "create")
	})
	for _, identifier := range identifiers {
		if created[identifier] {
			return identifier + " is also a value this plan creates, and " + reference.Origin + " indirection hides whether it is produced here"
		}
	}
	return ""
}

// samePlanTargets handles a reference to something this plan produces. It
// returns the identifiers the producers do not account for, or a verdict when
// the plan alone settles the reference.
func samePlanTargets(plan Plan, change PlannedValues, rule ExistenceRule, reference AttributeReference, outcome Result) ([]string, Result, bool) {
	// Terraform creates a producer before its consumer, so the target is absent
	// now by design.
	if decided, done := producerRefusal(plan, change, rule, reference, outcome); done {
		return nil, decided, true
	}
	// Look up only the identifiers the producers do not account for. A set
	// unknown as a whole may still hold literals the plan does not show.
	value, unknown := change.Route(rule.Route())
	external, visible := unproduced(value, unknown,
		plannedValues(plan, func(address string) bool { return contains(reference.Producers, baseAddress(address)) }), rule.Collection)
	if !visible {
		return nil, outcome.partial(rule.Attribute + " is unknown until apply, and the plan does not show whether it holds anything besides what " + strings.Join(reference.Producers, ", ") + " produce"), true
	}
	if len(external) == 0 {
		outcome.Verdict, outcome.Reason = VerdictSatisfiedByPlan, "the target is produced by "+strings.Join(reference.Producers, ", ")+" in this plan"
		return nil, outcome, true
	}
	return external, outcome, false
}

// producerRefusal decides a reference whose producer is missing from the plan,
// destroyed by it, or replaced with an identity not yet known.
func producerRefusal(plan Plan, change PlannedValues, rule ExistenceRule, reference AttributeReference, outcome Result) (Result, bool) {
	for _, producer := range reference.Producers {
		actions, known := plan.Actions[producer]
		if !known {
			return outcome.partial("the referenced producer " + producer + " is not in the plan"), true
		}
		deletes, creates := hasAction(actions, "delete"), hasAction(actions, "create")
		if deletes && !creates {
			outcome.Verdict, outcome.Reason = VerdictOrderingRisk, "the referenced producer "+producer+" is destroyed by this plan"
			outcome.Finding = orderingFinding(change.Address, rule, "is destroyed by this same plan")
			return outcome, true
		}
		if deletes && creates {
			if _, known := knownIdentifiers(change.Route(rule.Route())); !known {
				return outcome.partial("replacement dependency identity is unknown until apply"), true
			}
		}
	}
	return outcome, false
}

// inspectTargets asks AWS about each identifier. The first that is not plainly
// present decides.
func (e Engine) inspectTargets(ctx context.Context, plan Plan, change PlannedValues, rule ExistenceRule, identifiers []string, outcome Result) Result {
	for _, identifier := range identifiers {
		if decided, done := e.inspectTarget(ctx, plan, change, rule, identifier, outcome); done {
			return decided
		}
	}
	outcome.Verdict, outcome.Reason = VerdictSatisfied, "every referenced "+rule.TargetResource+" exists"
	return outcome
}

// inspectTarget decides one identifier; done is false when AWS has it and the
// next should be checked.
func (e Engine) inspectTarget(ctx context.Context, plan Plan, change PlannedValues, rule ExistenceRule, identifier string, outcome Result) (Result, bool) {
	// A literal can name something this plan destroys. Terraform draws no edge
	// between the two, so the deletion may run before this create.
	if destroyed := destroyedByPlan(plan, rule.TargetResource, rule.TargetAttribute, identifier); destroyed != "" {
		outcome.Verdict, outcome.Reason = VerdictOrderingRisk, identifier+" is destroyed by "+destroyed+" in this plan"
		outcome.Finding = orderingFinding(change.Address, rule, "is destroyed by "+destroyed+" in this same plan")
		return outcome, true
	}
	// Convert only now, so a planned or not-yet-known value is never parsed.
	value, refusal := rule.Key.LookupValue(identifier)
	if refusal != "" {
		return outcome.partial(identifier + " cannot be read as the lookup's key: " + refusal), true
	}
	existence, why := e.Resolver.Exists(ctx, rule.Lookup, e.Scope, value)
	switch existence {
	case Exists:
		return outcome, false
	case NotFound:
		return e.missing(plan, change, rule, identifier, why, outcome), true
	default:
		return outcome.partial("the target could not be inspected: " + why), true
	}
}

func (e Engine) missing(plan Plan, change PlannedValues, rule ExistenceRule, identifier, why string, outcome Result) Result {
	if !rule.Lookup.ProvesAbsence() {
		return outcome.partial("the lookup cannot prove absence: " + why)
	}
	// Rule out a create of the same identifier that no reference orders first.
	switch createdByValue(plan, rule, identifier) {
	case createdByValueMatch:
		outcome.Verdict, outcome.Reason = VerdictOrderingRisk, identifier+" is created by this plan without a reference, so Terraform does not order it first"
		outcome.Finding = orderingFinding(change.Address, rule, "is created by this same plan, but only by value, so Terraform does not create it first")
		return outcome
	case createdByValueUndecidable:
		return outcome.partial("this plan creates " + rule.TargetResource + " and its identifier cannot be compared")
	}
	outcome.Verdict, outcome.Reason = VerdictViolation, fmt.Sprintf("%s %s does not exist", rule.TargetResource, identifier)
	decision := e.Enforcement.Decide(BlockingInput{
		Rule: rule, Verdict: outcome.Verdict, ProviderVersion: e.ProviderVersion,
		ScopeResolved: true,
	})
	outcome.Finding = missingFinding(change.Address, rule, identifier, decision)
	return outcome
}

// knownIdentifiers returns the non-empty identifiers in a planned value;
// complete is false when any part is unknown until apply.
func knownIdentifiers(value, unknown any) (identifiers []string, complete bool) {
	if markedUnknown(unknown) {
		return nil, false
	}
	switch typed := value.(type) {
	case string:
		if typed == "" {
			return nil, true
		}
		return []string{typed}, true
	case []any:
		return knownElements(typed, unknown)
	case nil:
		return nil, true
	}
	return nil, false
}

func knownElements(elements []any, unknown any) ([]string, bool) {
	unknownElements, _ := unknown.([]any)
	var identifiers []string
	for index, element := range elements {
		if index < len(unknownElements) && markedUnknown(unknownElements[index]) {
			return nil, false
		}
		text, ok := element.(string)
		if !ok {
			return nil, false
		}
		if text != "" {
			identifiers = append(identifiers, text)
		}
	}
	return identifiers, true
}

// unproduced returns the identifiers in a same-plan value that its producers do
// not account for. visible is false for a set or list unknown as a whole.
func unproduced(value, unknown any, produced map[string]bool, collection bool) ([]string, bool) {
	if markedUnknown(unknown) {
		// An unknown scalar can only be a producer's output; an unknown
		// collection may also hold literals.
		return nil, !collection
	}
	switch typed := value.(type) {
	case nil:
		return nil, true
	case string:
		if typed == "" || produced[typed] {
			return nil, true
		}
		return []string{typed}, true
	case []any:
		return unproducedElements(typed, unknown, produced)
	}
	return nil, false
}

// An element unknown until apply is produced then, so it is skipped rather than
// making the list unreadable.
func unproducedElements(elements []any, unknown any, produced map[string]bool) ([]string, bool) {
	unknownElements, _ := unknown.([]any)
	var external []string
	for index, element := range elements {
		if index < len(unknownElements) && markedUnknown(unknownElements[index]) {
			continue
		}
		text, ok := element.(string)
		if !ok {
			return nil, false
		}
		if text != "" && !produced[text] {
			external = append(external, text)
		}
	}
	return external, true
}

// plannedValues collects every known string the selected changes hold, before
// and after. A reference may read any attribute of its producer, not only its
// id.
func plannedValues(plan Plan, selected func(address string) bool) map[string]bool {
	values := map[string]bool{}
	for address, change := range plan.Changes {
		if !selected(address) {
			continue
		}
		collectStrings(change.After, values)
		if !hasAction(change.Actions, "create") {
			collectStrings(change.Before, values)
		}
	}
	return values
}

func collectStrings(value any, into map[string]bool) {
	switch typed := value.(type) {
	case string:
		if typed != "" {
			into[typed] = true
		}
	case []any:
		for _, element := range typed {
			collectStrings(element, into)
		}
	case map[string]any:
		for _, element := range typed {
			collectStrings(element, into)
		}
	}
}

func contains(list []string, wanted string) bool {
	for _, item := range list {
		if item == wanted {
			return true
		}
	}
	return false
}

// destroyedByPlan names a planned destruction of resourceType whose prior
// attribute equals identifier.
func destroyedByPlan(plan Plan, resourceType, attribute, identifier string) string {
	for address, change := range plan.Changes {
		if change.ResourceType != resourceType || !hasAction(change.Actions, "delete") {
			continue
		}
		if value, ok := change.Before[attribute].(string); ok && value == identifier {
			return address
		}
	}
	return ""
}

// valueCreation is whether this plan may create a target under a literal
// identifier, with no reference ordering the create first.
type valueCreation int

const (
	notCreatedByValue valueCreation = iota
	createdByValueMatch
	// The planned create's identity cannot be compared with the identifier.
	createdByValueUndecidable
)

func createdByValue(plan Plan, rule ExistenceRule, identifier string) valueCreation {
	if rule.TargetIdentity == IdentityServerGenerated {
		return notCreatedByValue
	}
	undecidable := false
	for _, change := range plan.Changes {
		if change.ResourceType != rule.TargetResource || !hasAction(change.Actions, "create") {
			continue
		}
		if rule.TargetIdentity == IdentityUnknown || rule.TargetIdentity == "" {
			undecidable = true
			continue
		}
		if value, ok := change.After[rule.TargetIdentity].(string); ok {
			if value == identifier {
				return createdByValueMatch
			}
			continue
		}
		undecidable = true
	}
	if undecidable {
		return createdByValueUndecidable
	}
	return notCreatedByValue
}

func hasAction(actions []string, wanted string) bool {
	for _, action := range actions {
		if action == wanted {
			return true
		}
	}
	return false
}

func missingFinding(address string, rule ExistenceRule, identifier string, decision BlockingDecision) *model.Finding {
	// Severity and confidence are how this engine says "blocking"; the report
	// and the CLI only read them.
	severity, confidence := model.SeverityWarning, model.ConfidenceMedium
	explanation := "This reference is a real dependency, but tfpreflight has not verified that AWS refuses the create when the target is absent, so it is reported without blocking."
	if decision.Blocking {
		severity, confidence = model.SeverityError, model.ConfidenceHigh
		explanation = fmt.Sprintf("The create path calls %s:%s, and AWS was observed to reject it when this reference's target was absent.",
			rule.CreateService, rule.CreateOperation)
	}
	return &model.Finding{
		ID: "aws.dependency-missing", Provider: "aws", Resource: address, Category: "dependency",
		Severity: severity, Confidence: confidence,
		Title:       "Referenced resource does not exist",
		Operation:   "Create " + model.WithArticle(model.ResourceName(rule.Resource)),
		Problem:     fmt.Sprintf("%s refers to %s %s, which AWS reports does not exist.", rule.Attribute, model.WithArticle(model.ResourceName(rule.TargetResource)), identifier),
		Explanation: explanation,
		Remediation: fmt.Sprintf("Correct %s, or create the %s before applying.", rule.Attribute, model.ResourceName(rule.TargetResource)),
		Notes:       []string{decision.Reason},
		Brief:       fmt.Sprintf("%s refers to %s %s, which does not exist.", rule.Attribute, model.ResourceName(rule.TargetResource), identifier),
		Next:        fmt.Sprintf("Fix: correct %s, or create the %s first.", rule.Attribute, model.ResourceName(rule.TargetResource)),
	}
}

func orderingFinding(address string, rule ExistenceRule, detail string) *model.Finding {
	return &model.Finding{
		ID: "aws.dependency-ordering", Provider: "aws", Resource: address, Category: "dependency",
		Severity: model.SeverityWarning, Confidence: model.ConfidenceMedium,
		Title:       "Dependency is not ordered by Terraform",
		Operation:   "Create " + model.WithArticle(model.ResourceName(rule.Resource)),
		Problem:     fmt.Sprintf("%s refers to %s that %s.", rule.Attribute, model.WithArticle(model.ResourceName(rule.TargetResource)), detail),
		Explanation: "Terraform orders resources only through references. A value written directly creates no ordering, so the outcome depends on apply timing.",
		Remediation: fmt.Sprintf("Set %s from the %s resource's attribute instead of a literal value.", rule.Attribute, rule.TargetResource),
		Brief:       fmt.Sprintf("%s refers to %s that %s.", rule.Attribute, model.WithArticle(model.ResourceName(rule.TargetResource)), detail),
		Next:        fmt.Sprintf("Fix: set %s from the %s resource's attribute, not a literal value.", rule.Attribute, rule.TargetResource),
	}
}
