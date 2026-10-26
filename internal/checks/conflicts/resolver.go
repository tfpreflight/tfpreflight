// Package conflicts decides whether a planned create would collide with a
// resource AWS already has. The reasoning here is the same for every service; a
// service adds only an AWS lookup.
package conflicts

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/tfpreflight/tfpreflight/rules"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// Outcome is what a lookup established about the planned identity.
type Outcome string

const (
	// OutcomeExists means AWS confirmed an object with this identity.
	OutcomeExists Outcome = "exists"
	// OutcomeNotFound means AWS confirmed there is no such object.
	OutcomeNotFound Outcome = "not_found"
	// OutcomeUnknown means the question could not be answered. It is never read
	// as absence: a denied or throttled lookup says nothing about whether the
	// object is there.
	OutcomeUnknown Outcome = "unknown"
)

// Create semantics, established per resource; see the rules package.
const (
	SemanticsDuplicateError = rules.SemanticsDuplicateError
	SemanticsIdempotent     = rules.SemanticsIdempotent
	SemanticsUpsert         = rules.SemanticsUpsert
	SemanticsInconclusive   = rules.SemanticsInconclusive
)

// Trust levels, mirroring the permission model.
const (
	TrustGenerated = "generated"
	TrustVerified  = "verified"
)

// IdentityPart is one part of a composite identity: the planned attribute and
// the lookup field it fills.
type IdentityPart struct {
	Attribute   string `json:"terraform_attribute"`
	LookupField string `json:"lookup_field"`
}

// Identity is what makes a resource unique: one field, or the parts of a
// composite identity.
type Identity struct {
	Type  string         `json:"type,omitempty"`
	Parts []IdentityPart `json:"parts,omitempty"`
}

// Composite reports whether the identity has more than one part.
func (i Identity) Composite() bool { return len(i.Parts) > 1 }

// Rule is what is known about one resource type's create conflicts.
type Rule struct {
	ProviderVersion string `json:"provider_version"`
	ResourceType    string `json:"resource_type"`
	IdentityField   string `json:"identity_field"`
	LookupService   string `json:"lookup_service"`
	LookupOperation string `json:"lookup_operation"`
	CreateSemantics string `json:"create_semantics"`
	Scope           string `json:"scope"`
	Trust           string `json:"trust"`
	// Identity holds a composite identity. A single-field rule leaves it empty
	// and uses IdentityField.
	Identity Identity `json:"identity,omitempty"`
}

func (r Rule) parts() []IdentityPart {
	if len(r.Identity.Parts) > 0 {
		return r.Identity.Parts
	}
	return []IdentityPart{{Attribute: r.IdentityField}}
}

// LookupRequest is what an adapter needs to answer. Identity is a single-part
// identity; Values holds every part by the lookup field it fills, for composite
// adapters.
type LookupRequest struct {
	Operation string
	Identity  string
	Values    map[string]string
}

// LookupAdapter performs one service's AWS lookup and nothing else: no
// Terraform, severity or message logic.
type LookupAdapter interface {
	Service() string
	Supports(operation string) bool
	Lookup(ctx context.Context, request LookupRequest) (Outcome, error)
}

// Registry dispatches a rule's lookup to the adapter for its service.
type Registry struct{ adapters map[string][]LookupAdapter }

// NewRegistry returns an empty adapter registry.
func NewRegistry() *Registry { return &Registry{adapters: map[string][]LookupAdapter{}} }

// Register adds service adapters.
func (r *Registry) Register(adapters ...LookupAdapter) {
	for _, adapter := range adapters {
		service := adapter.Service()
		r.adapters[service] = append(r.adapters[service], adapter)
	}
}

// For finds the adapter for a service operation.
func (r *Registry) For(service, operation string) (LookupAdapter, bool) {
	for _, adapter := range r.adapters[service] {
		if adapter.Supports(operation) {
			return adapter, true
		}
	}
	return nil, false
}

// Services lists the registered service names.
func (r *Registry) Services() []string {
	services := make([]string, 0, len(r.adapters))
	for service := range r.adapters {
		services = append(services, service)
	}
	sort.Strings(services)
	return services
}

// Status records why a planned change was or was not conflict-checked.
type Status string

// Conflict coverage statuses.
const (
	StatusChecked              Status = "checked"
	StatusNoRule               Status = "no_rule"
	StatusSemanticsNotProven   Status = "semantics_not_proven"
	StatusAdapterMissing       Status = "adapter_missing"
	StatusIdentityUnknown      Status = "identity_unknown"
	StatusLookupFailed         Status = "lookup_failed"
	StatusCompositeSupported   Status = "composite_supported"
	StatusCompositePartUnknown Status = "composite_part_unknown"
	// StatusNoConflictPossible means AWS accepts a create over an existing
	// identity (idempotent or upsert), so a duplicate cannot fail it.
	StatusNoConflictPossible Status = "no_conflict_possible"
	// StatusContextUnresolved means the run's AWS account or region is
	// unresolved, so no lookup was sent.
	StatusContextUnresolved Status = "context_unresolved"
)

// CheckStatus is how a resolver result reads in the coverage report.
func (s Status) CheckStatus() model.CheckStatus {
	switch s {
	case StatusChecked, StatusCompositeSupported:
		return model.CheckChecked
	case StatusLookupFailed, StatusIdentityUnknown, StatusCompositePartUnknown:
		return model.CheckUnverifiable
	case StatusSemanticsNotProven, StatusAdapterMissing:
		return model.CheckUnsupported
	case StatusContextUnresolved:
		return model.CheckPartialAWSContext
	default:
		return model.CheckNotApplicable
	}
}

// Coverage is whether one resource was conflict-checked, and why.
type Coverage struct {
	Resource string
	Status   Status
	Detail   string
}

// Resolver applies conflict rules to a plan.
type Resolver struct {
	rules    map[string]Rule
	registry *Registry
}

// NewResolver builds a resolver for one provider version's rules.
func NewResolver(rules []Rule, registry *Registry) *Resolver {
	indexed := make(map[string]Rule, len(rules))
	for _, rule := range rules {
		indexed[rule.ResourceType] = rule
	}
	return &Resolver{rules: indexed, registry: registry}
}

// Check evaluates every planned create and returns findings and coverage.
func (r *Resolver) Check(ctx context.Context, changes []model.PlannedChange) ([]model.Finding, []Coverage) {
	var findings []model.Finding
	coverage := make([]Coverage, 0, len(changes))
	for _, change := range changes {
		if change.Action != model.ActionCreate {
			continue
		}
		finding, entry := r.checkChange(ctx, change)
		coverage = append(coverage, entry)
		if finding != nil {
			findings = append(findings, *finding)
		}
	}
	return findings, coverage
}

func (r *Resolver) checkChange(ctx context.Context, change model.PlannedChange) (*model.Finding, Coverage) {
	rule, found := r.rules[change.ResourceType]
	if !found {
		return nil, Coverage{change.Address, StatusNoRule, "no conflict rule for this resource type"}
	}
	if status, reason := semanticsGate(rule); status != "" {
		return nil, Coverage{change.Address, status, reason}
	}
	values, ordered, unknownPart := identityValues(change, rule)
	if unknownPart != "" {
		status := StatusIdentityUnknown
		if rule.Identity.Composite() {
			status = StatusCompositePartUnknown
		}
		return nil, Coverage{change.Address, status, "planned " + unknownPart + " is not known before apply"}
	}
	if r.registry == nil {
		return nil, Coverage{change.Address, StatusContextUnresolved, "AWS account or region unresolved; no lookup sent"}
	}
	adapter, found := r.registry.For(rule.LookupService, rule.LookupOperation)
	if !found {
		return nil, Coverage{change.Address, StatusAdapterMissing, "no adapter for " + rule.LookupService + ":" + rule.LookupOperation}
	}
	single := ""
	if !rule.Identity.Composite() {
		single = values[firstKey(values)]
	}
	outcome, err := adapter.Lookup(ctx, LookupRequest{Operation: rule.LookupOperation, Identity: single, Values: values})
	switch outcome {
	case OutcomeExists:
		finding := conflictFinding(change, rule, ordered)
		return &finding, Coverage{change.Address, checkedStatus(rule), "identity already exists"}
	case OutcomeNotFound:
		return nil, Coverage{change.Address, checkedStatus(rule), "identity is available"}
	default:
		finding := lookupUnavailable(change, rule, ordered[0], err)
		return &finding, Coverage{change.Address, StatusLookupFailed, lookupErrorText(err)}
	}
}

// semanticsGate returns the coverage status for a rule whose create semantics
// rule out a conflict, or "" when a duplicate is proven to fail. Idempotent and
// upsert creates succeed over an existing object.
func semanticsGate(rule Rule) (Status, string) {
	switch rule.CreateSemantics {
	case SemanticsIdempotent, SemanticsUpsert:
		return StatusNoConflictPossible, "create semantics are " + rule.CreateSemantics
	case SemanticsDuplicateError:
		return "", ""
	default:
		return StatusSemanticsNotProven, "create semantics are " + orUnknown(rule.CreateSemantics)
	}
}

// identityValues reads each identity part from the plan, by lookup field, with
// "attribute = value" lines in part order. unknownPart names the first part not
// known before apply: guessing a part would look up a different object.
func identityValues(change model.PlannedChange, rule Rule) (values map[string]string, ordered []string, unknownPart string) {
	values = map[string]string{}
	for _, part := range rule.parts() {
		value, ok := plannedIdentity(change, part.Attribute)
		if !ok {
			return nil, nil, part.Attribute
		}
		field := part.LookupField
		if field == "" {
			field = part.Attribute
		}
		values[field] = value
		ordered = append(ordered, part.Attribute+" = "+value)
	}
	return values, ordered, ""
}

func checkedStatus(rule Rule) Status {
	if rule.Identity.Composite() {
		return StatusCompositeSupported
	}
	return StatusChecked
}

// plannedIdentity reads the identity from the plan, refusing a value not known
// before apply: a generated name cannot be predicted.
func plannedIdentity(change model.PlannedChange, field string) (string, bool) {
	if unknownAttribute(change.AfterUnknown, field) {
		return "", false
	}
	after, ok := change.After.(map[string]any)
	if !ok {
		return "", false
	}
	value, ok := after[field].(string)
	if !ok || strings.TrimSpace(value) == "" {
		return "", false
	}
	return value, true
}

func unknownAttribute(afterUnknown any, field string) bool {
	unknown, ok := afterUnknown.(map[string]any)
	if !ok {
		return false
	}
	flag, ok := unknown[field].(bool)
	return ok && flag
}

func firstKey(values map[string]string) string {
	for key := range values {
		return key
	}
	return ""
}

// conflictFinding reports a conflict. Severity follows trust: a rule proven
// against AWS blocks, a generated one warns.
func conflictFinding(change model.PlannedChange, rule Rule, ordered []string) model.Finding {
	severity, confidence := model.SeverityWarning, model.ConfidenceMedium
	explanation := "Terraform plans to create this resource with an identity AWS already has. This conflict rule was generated from provider source and AWS metadata and has not been independently verified."
	if rule.Trust == TrustVerified {
		severity, confidence = model.SeverityError, model.ConfidenceHigh
		explanation = "Terraform plans to create this resource with an identity AWS already has, and AWS is proven to reject a duplicate."
	}
	problem := fmt.Sprintf("%s %q already exists.", model.Sentence(change.ResourceType), strings.TrimPrefix(ordered[0], attributeName(ordered[0])+" = "))
	remediation := "Use a different " + rule.IdentityField + ", or import the existing resource if Terraform should manage it."
	brief, next := problem, "Fix: use a different "+rule.IdentityField+", or import the existing resource."
	if rule.Identity.Composite() {
		problem = model.Sentence(model.WithArticle(model.ResourceName(change.ResourceType))) + " with this identity already exists."
		remediation = "Change one of the identity values, or import the existing resource if Terraform should manage it."
		brief = model.Sentence(model.WithArticle(model.ResourceName(change.ResourceType))) + " with " + strings.Join(ordered, ", ") + " already exists."
		next = "Fix: change one of these values, or import the existing resource."
	}
	return model.Finding{
		ID:          "aws.identity-conflict",
		Provider:    "aws",
		Resource:    change.Address,
		Category:    "resource-conflict",
		Severity:    severity,
		Confidence:  confidence,
		Title:       "Apply will likely fail",
		Operation:   "Create " + model.WithArticle(model.ResourceName(change.ResourceType)),
		Problem:     problem,
		Explanation: explanation,
		Remediation: remediation,
		Notes:       identityNotes(ordered),
		Brief:       brief,
		Next:        next,
	}
}

// lookupUnavailable reports a lookup that could not be answered. It is
// informational: an unanswered lookup is evidence of nothing.
func lookupUnavailable(change model.PlannedChange, _ Rule, identity string, err error) model.Finding {
	return model.Finding{
		ID:          "aws.identity-conflict-unavailable",
		Provider:    "aws",
		Resource:    change.Address,
		Category:    "resource-conflict",
		Severity:    model.SeverityInfo,
		Confidence:  model.ConfidenceLow,
		Title:       "Existing-resource check could not be completed",
		Explanation: "Could not determine whether " + identity + " already exists, so this conflict was not checked.",
		Notes:       []string{lookupErrorText(err)},
		AWSError:    lookupErrorText(err),
		Brief:       "Could not check whether " + identity + " already exists.",
		Next:        "Check: the lookup got no answer from AWS; details: tfpreflight check --details",
	}
}

// identityNotes puts each identity part on its own line, so a composite identity
// reads as a list.
func identityNotes(ordered []string) []string {
	notes := make([]string, 0, len(ordered)+1)
	notes = append(notes, "Identity:")
	return append(notes, ordered...)
}

func attributeName(entry string) string {
	name, _, _ := strings.Cut(entry, " = ")
	return name
}

func lookupErrorText(err error) string {
	if err == nil {
		return "the lookup returned no decision"
	}
	return err.Error()
}

func orUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}
