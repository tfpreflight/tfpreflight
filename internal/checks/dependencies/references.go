// Package dependencies predicts apply failures from the environment around a
// planned change: referenced resources that do not exist.
//
// The hard part is knowing when not to ask AWS. A reference to something the
// same plan creates is absent before apply by design, and calling it missing
// would be this check's most common false finding. So everything starts from
// what Terraform recorded about where each value comes from.
package dependencies

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

const (
	// OriginLiteral is a constant written in configuration.
	OriginLiteral = "literal"
	// OriginVariable is an input variable: resolved at plan time, never produced
	// by a resource.
	OriginVariable = "variable"
	// OriginLocal is a local value. The plan does not record a local's own
	// expression, so a resource behind it cannot be seen.
	OriginLocal = "local"
	// OriginDataSource is a value read by a data source.
	OriginDataSource = "data-source"
	// OriginSamePlan is a value produced by a managed resource in this plan.
	OriginSamePlan = "same-plan"
	// OriginModuleOutput is a child module's output, whose producer cannot be
	// named from the parent.
	OriginModuleOutput = "module-output"
	// OriginUnknown is anything else, including computed expressions.
	OriginUnknown = "unknown"
)

// AttributeReference records where one attribute's planned value comes from.
type AttributeReference struct {
	Attribute string
	Origin    string
	// ExternalModuleInput is true only when the module call passes constants for
	// every input referenced; other module inputs may hide producers in this
	// plan.
	ExternalModuleInput bool
	// Producers are the managed resources the value is drawn from, by address
	// without instance keys.
	Producers []string
}

// Plan is the part of `terraform show -json` the dependency check reads.
type Plan struct {
	// DefaultContext comes from the provider configuration, never from the IAM
	// simulation principal.
	DefaultContext ProviderContext
	References     map[string]map[string]AttributeReference
	// Actions are every action planned for a resource's instances, by address
	// without instance keys, so a producer can be judged created, kept or
	// destroyed.
	Actions map[string][]string
	Changes map[string]PlannedValues
	// Providers is the provider configuration Terraform resolved for each
	// change: "aws" for the default, "aws.west" for an alias, including one a
	// module received.
	Providers map[string]string
}

// DefaultProvider is the configuration key of the unaliased AWS provider.
const DefaultProvider = model.DefaultAWSProviderKey

// PlannedValues is one resource change as the dependency check needs it.
type PlannedValues struct {
	Address      string
	ResourceType string
	Actions      []string
	Before       map[string]any
	After        map[string]any
	AfterUnknown map[string]any
}

type expression struct {
	ConstantValue any      `json:"constant_value"`
	References    []string `json:"references"`
}

type configResource struct {
	Address           string                     `json:"address"`
	Mode              string                     `json:"mode"`
	Type              string                     `json:"type"`
	Name              string                     `json:"name"`
	ProviderConfigKey string                     `json:"provider_config_key"`
	Expressions       map[string]json.RawMessage `json:"expressions"`
}

type configModule struct {
	Resources   []configResource `json:"resources"`
	ModuleCalls map[string]struct {
		Module      configModule          `json:"module"`
		Expressions map[string]expression `json:"expressions"`
	} `json:"module_calls"`
}

type planDocument struct {
	Variables map[string]struct {
		Value any `json:"value"`
	} `json:"variables"`
	Configuration struct {
		Providers map[string]struct {
			Expressions map[string]json.RawMessage `json:"expressions"`
		} `json:"provider_config"`
		RootModule configModule `json:"root_module"`
	} `json:"configuration"`
	ResourceChanges []struct {
		Address       string `json:"address"`
		ModuleAddress string `json:"module_address"`
		Mode          string `json:"mode"`
		Type          string `json:"type"`
		Name          string `json:"name"`
		Change        struct {
			Actions      []string       `json:"actions"`
			Before       map[string]any `json:"before"`
			After        map[string]any `json:"after"`
			AfterUnknown map[string]any `json:"after_unknown"`
		} `json:"change"`
	} `json:"resource_changes"`
}

var instanceKey = regexp.MustCompile(`\[[^\]]*\]`)

// baseAddress drops instance keys: aws_subnet.x[0] and aws_subnet.x["a"] both
// belong to aws_subnet.x.
func baseAddress(address string) string { return instanceKey.ReplaceAllString(address, "") }

// ParsePlan reads the reference structure Terraform recorded for a plan.
// Terraform's JSON says, per attribute, whether a value is a constant or which
// objects it references; that is the only reliable way to tell a parent this
// plan creates from one that already exists.
func ParsePlan(data []byte) (Plan, error) {
	var document planDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return Plan{}, fmt.Errorf("parse plan JSON: %w", err)
	}
	blocks := map[string]configResource{}
	collectBlocks(document.Configuration.RootModule, "", blocks)
	moduleInputs := map[string]map[string]expression{}
	collectModuleInputs(document.Configuration.RootModule, "", moduleInputs)

	plan := Plan{References: map[string]map[string]AttributeReference{}, Actions: map[string][]string{}, Changes: map[string]PlannedValues{}, Providers: map[string]string{}}
	plan.DefaultContext = providerContext(document)
	for _, change := range document.ResourceChanges {
		if change.Mode != "" && change.Mode != "managed" {
			continue
		}
		base := baseAddress(change.Address)
		plan.Actions[base] = append(plan.Actions[base], change.Change.Actions...)
		plan.Changes[change.Address] = PlannedValues{
			Address: change.Address, ResourceType: change.Type, Actions: change.Change.Actions,
			Before: change.Change.Before, After: change.Change.After, AfterUnknown: change.Change.AfterUnknown,
		}
		modulePath := baseAddress(change.ModuleAddress)
		block, found := blocks[qualify(modulePath, change.Type+"."+change.Name)]
		if !found {
			continue
		}
		plan.Providers[change.Address] = block.ProviderConfigKey
		plan.References[change.Address] = attributeReferences(block, modulePath, moduleInputs[modulePath])
	}
	return plan, nil
}

func attributeReferences(block configResource, modulePath string, inputs map[string]expression) map[string]AttributeReference {
	references := map[string]AttributeReference{}
	for attribute, expr := range collectExpressions(block.Expressions, "", 0) {
		ref := classify(attribute, expr, modulePath)
		if ref.Origin == OriginVariable && modulePath != "" {
			ref.ExternalModuleInput = constantModuleInputs(expr, inputs)
		}
		references[attribute] = ref
	}
	return references
}

// constantModuleInputs reports whether the module call passes a constant for
// every variable an expression inside the module reads.
func constantModuleInputs(expr expression, inputs map[string]expression) bool {
	for _, input := range expr.References {
		name := strings.SplitN(strings.TrimPrefix(input, "var."), ".", 2)[0]
		value, found := inputs[name]
		if !found || value.ConstantValue == nil || len(value.References) > 0 {
			return false
		}
	}
	return true
}

func collectModuleInputs(module configModule, path string, inputs map[string]map[string]expression) {
	for name, call := range module.ModuleCalls {
		child := qualify(path, "module."+name)
		inputs[child] = call.Expressions
		collectModuleInputs(call.Module, child, inputs)
	}
}

// collectExpressions flattens a resource's configured arguments, nested blocks
// included, to their schema paths. A repeated block's instances describe one
// argument between them, so their expressions are merged under one path: what
// matters is where values come from, not which instance supplied them.
func collectExpressions(raw map[string]json.RawMessage, prefix string, depth int) map[string]expression {
	collected := map[string]expression{}
	if depth > 6 {
		return collected
	}
	for name, value := range raw {
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		var leaf expression
		if json.Unmarshal(value, &leaf) == nil && (leaf.ConstantValue != nil || leaf.References != nil) {
			collected[path] = leaf
			continue
		}
		for _, block := range nestedBlocks(value) {
			for nestedPath, nested := range collectExpressions(block, path, depth+1) {
				collected[nestedPath] = mergeExpressions(collected[nestedPath], nested)
			}
		}
	}
	return collected
}

func nestedBlocks(value json.RawMessage) []map[string]json.RawMessage {
	var many []map[string]json.RawMessage
	if json.Unmarshal(value, &many) == nil {
		return many
	}
	var one map[string]json.RawMessage
	if json.Unmarshal(value, &one) == nil {
		return []map[string]json.RawMessage{one}
	}
	return nil
}

// mergeExpressions combines what a repeated block's instances say about one
// argument: every reference, and a constant only while none of them references
// anything.
func mergeExpressions(existing, addition expression) expression {
	merged := expression{ConstantValue: existing.ConstantValue}
	if merged.ConstantValue == nil {
		merged.ConstantValue = addition.ConstantValue
	}
	merged.References = append(append([]string(nil), existing.References...), addition.References...)
	return merged
}

func collectBlocks(module configModule, path string, blocks map[string]configResource) {
	for _, resource := range module.Resources {
		if resource.Mode != "managed" {
			continue
		}
		blocks[qualify(path, resource.Type+"."+resource.Name)] = resource
	}
	for name, call := range module.ModuleCalls {
		collectBlocks(call.Module, qualify(path, "module."+name), blocks)
	}
}

func qualify(modulePath, address string) string {
	if modulePath == "" {
		return address
	}
	return modulePath + "." + address
}

func classify(attribute string, expr expression, modulePath string) AttributeReference {
	reference := AttributeReference{Attribute: attribute}
	if len(expr.References) == 0 {
		if expr.ConstantValue != nil {
			reference.Origin = OriginLiteral
		} else {
			reference.Origin = OriginUnknown
		}
		return reference
	}
	origins := map[string]bool{}
	seen := map[string]bool{}
	for _, raw := range expr.References {
		if origin, ok := symbolOrigin(raw); ok {
			origins[origin] = true
			continue
		}
		parts := strings.SplitN(baseAddress(raw), ".", 3)
		if len(parts) < 2 || !strings.Contains(parts[0], "_") {
			origins[OriginUnknown] = true
			continue
		}
		producer := qualify(modulePath, parts[0]+"."+parts[1])
		if !seen[producer] {
			seen[producer] = true
			reference.Producers = append(reference.Producers, producer)
		}
		origins[OriginSamePlan] = true
	}
	reference.Origin = dominantOrigin(origins)
	return reference
}

// symbolOrigins maps each namespace a reference can start with, other than a
// managed resource type, to the origin it implies.
var symbolOrigins = []struct{ prefix, origin string }{
	{"var.", OriginVariable},
	{"local.", OriginLocal},
	{"data.", OriginDataSource},
	{"module.", OriginModuleOutput},
	{"each.", OriginUnknown},
	{"count.", OriginUnknown},
	{"path.", OriginUnknown},
	{"terraform.", OriginUnknown},
	{"self.", OriginUnknown},
}

func symbolOrigin(reference string) (string, bool) {
	for _, symbol := range symbolOrigins {
		if strings.HasPrefix(reference, symbol.prefix) {
			return symbol.origin, true
		}
	}
	return "", false
}

// originPrecedence decides an expression that combines origins. A producer in
// this plan wins: a value drawn from something this plan creates is absent
// before apply whatever else it combines.
var originPrecedence = []string{OriginSamePlan, OriginModuleOutput, OriginUnknown, OriginLocal, OriginDataSource}

func dominantOrigin(origins map[string]bool) string {
	for _, origin := range originPrecedence {
		if origins[origin] {
			return origin
		}
	}
	return OriginVariable
}

// Route is the planned value at a rule's schema path, and its unknown markers.
func (p PlannedValues) Route(path []string) (value, unknown any) {
	if len(path) == 0 {
		return nil, nil
	}
	if len(path) == 1 {
		// A top-level argument is read exactly as Terraform wrote it, unknown
		// markers and all.
		return p.After[path[0]], p.AfterUnknown[path[0]]
	}
	return routeValues(p.After, p.AfterUnknown, path)
}

// routeValues walks a planned object by path and flattens what it finds. A block
// may repeat, so one path can hold values from several instances. Anything the
// plan does not show makes the whole path unknown rather than a shorter list: a
// missing element must never be read as absent.
func routeValues(value, unknown any, path []string) (any, any) {
	walk := routeWalk{known: true}
	walk.visit(value, unknown, path)
	return walk.values, !walk.known
}

type routeWalk struct {
	values []any
	known  bool
}

func (w *routeWalk) visit(value, unknown any, rest []string) {
	if markedUnknown(unknown) {
		w.known = false
		return
	}
	if len(rest) == 0 {
		w.collect(value, unknown)
		return
	}
	switch typed := value.(type) {
	case map[string]any:
		w.descend(typed, unknown, rest)
	case []any:
		// A repeated block: every instance answers the same path.
		markers, _ := unknown.([]any)
		for index, element := range typed {
			var elementUnknown any
			if index < len(markers) {
				elementUnknown = markers[index]
			}
			w.visit(element, elementUnknown, rest)
		}
	case nil:
	default:
		w.known = false
	}
}

func (w *routeWalk) collect(value, unknown any) {
	switch typed := value.(type) {
	case []any:
		w.values = append(w.values, typed...)
	case nil:
	default:
		w.values = append(w.values, typed)
	}
	if markers, ok := unknown.([]any); ok {
		for _, marker := range markers {
			if markedUnknown(marker) {
				w.known = false
			}
		}
	}
}

func (w *routeWalk) descend(object map[string]any, unknown any, rest []string) {
	var nextUnknown any
	if markers, ok := unknown.(map[string]any); ok {
		nextUnknown = markers[rest[0]]
	}
	next, present := object[rest[0]]
	if !present {
		// Terraform omits an argument it cannot know yet and marks it unknown.
		// Absent and unknown is unknown, not empty.
		if nextUnknown != nil {
			w.visit(nil, nextUnknown, rest[1:])
		}
		return
	}
	w.visit(next, nextUnknown, rest[1:])
}

func markedUnknown(marker any) bool {
	flag, ok := marker.(bool)
	return ok && flag
}
