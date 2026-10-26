package permissions

// IAM decides a request against the resource it names and the context it
// carries. Simulating every action against "*" with no context would report a
// policy that allows an action only on some resources, or only for some tags, as
// a denial. So the resource's ARN is built from AWS's ARN formats and what the
// plan knows, and the known context keys are passed. What cannot be built is
// simulated against "*", and a denial there is never reported as certain.

import (
	"encoding/json"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/tfpreflight/tfpreflight/internal/packs"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// Scope is where the apply creates resources.
type Scope struct {
	Partition string
	Region    string
	Account   string
}

type iamResource struct {
	Type    string   `json:"type"`
	Formats []string `json:"formats"`
}

type iamAction struct {
	Resources     []iamResource `json:"resources"`
	ConditionKeys []string      `json:"condition_keys"`
}

var (
	actionsOnce sync.Once
	actions     map[string]iamAction
)

// loadActions reads aws/iam/actions.json. Without it, every action is simulated
// against "*".
func loadActions() map[string]iamAction {
	actionsOnce.Do(func() {
		data, err := packs.ReadFile("aws/iam/actions.json")
		if err != nil {
			return
		}
		var file struct {
			Actions map[string]iamAction `json:"actions"`
		}
		if json.Unmarshal(data, &file) == nil {
			actions = file.Actions
		}
	})
	return actions
}

type target struct {
	ARN string
	// Exact means the decision for ARN is the one AWS will make: a real ARN, or
	// "*" for an action AWS authorizes only against "*".
	Exact bool
	// Own means ARN is the planned resource's own.
	Own bool
	// Reason is why the ARN could not be built, when it is "*" and not exact.
	Reason string
}

var formatVariable = regexp.MustCompile(`\$\{([A-Za-z0-9]+)\}`)

func targetFor(r plannedPermission, scope Scope, known map[string]iamAction) target {
	action, ok := known[strings.ToLower(r.operation.Permission)]
	if !ok {
		return target{ARN: "*", Reason: "AWS's service reference does not describe " + r.operation.Permission}
	}
	if len(action.Resources) == 0 {
		return target{ARN: "*", Exact: true}
	}
	// The resource type that is the planned resource itself; otherwise a
	// resource the plan names by ARN.
	for _, resource := range action.Resources {
		if !sameType(r.change.ResourceType, resource.Type) {
			continue
		}
		for _, format := range resource.Formats {
			if arn, ok := fill(format, scope, r, true); ok {
				return target{ARN: arn, Exact: true, Own: true}
			}
		}
		return target{ARN: "*", Reason: "the " + resource.Type + " ARN depends on values not known until apply"}
	}
	// A resource the action acts on that the plan names by its ARN, or by the
	// values its ARN is made of.
	for _, resource := range action.Resources {
		if arn, ok := referencedARN(r.change, resource.Formats); ok {
			return target{ARN: arn, Exact: true}
		}
	}
	if len(action.Resources) == 1 {
		for _, format := range action.Resources[0].Formats {
			if arn, ok := fill(format, scope, r, false); ok {
				return target{ARN: arn, Exact: true}
			}
		}
	}
	return target{ARN: "*", Reason: r.operation.Permission + " acts on a " + action.Resources[0].Type + " the plan does not name by a known ARN"}
}

// sameType reports whether an AWS resource type is the Terraform one:
// aws_iam_role is a role, aws_cloudwatch_log_group a log-group.
func sameType(terraformType, awsType string) bool {
	normal := func(s string) string {
		return strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(s))
	}
	return strings.HasSuffix(normal(strings.TrimPrefix(terraformType, "aws_")), normal(awsType))
}

// fill substitutes a format's variables from the scope and the planned values.
// own says the format is the planned resource's own, so its bare name attribute
// is its name. Any unknown variable fails the whole ARN.
func fill(format string, scope Scope, r plannedPermission, own bool) (string, bool) {
	ok := true
	values := 0
	scopeValues := map[string]string{"Partition": scope.Partition, "Region": scope.Region, "Account": scope.Account}
	arn := formatVariable.ReplaceAllStringFunc(format, func(match string) string {
		name := match[2 : len(match)-1]
		if value, isScope := scopeValues[name]; isScope {
			if value == "" {
				ok = false
			}
			return value
		}
		values++
		value, known := nameValue(r, strings.TrimSuffix(name, "WithPath"), own)
		if !known {
			ok = false
			return ""
		}
		if strings.HasSuffix(name, "WithPath") {
			path, known := pathValue(r)
			if !known {
				ok = false
				return ""
			}
			return strings.TrimPrefix(path, "/") + value
		}
		return value
	})
	return arn, ok && values > 0
}

// nameValue is the planned value an ARN variable names. AWS names it after the
// value (FunctionName, BucketName); the resource holds it in snake case
// (function_name), as its own name, or as the noun alone (bucket). Only an
// attribute the resource has, with a known value, counts.
func nameValue(r plannedPermission, variable string, own bool) (string, bool) {
	candidates := []string{snake(variable)}
	if noun, ok := strings.CutSuffix(variable, "Name"); ok && noun != "" {
		if own {
			candidates = append(candidates, "name")
		}
		candidates = append(candidates, snake(noun))
	}
	for _, candidate := range candidates {
		if !hasAttribute(r, candidate) {
			continue
		}
		return packs.ValueForField(r.change, candidate)
	}
	return "", false
}

func hasAttribute(r plannedPermission, name string) bool {
	if len(r.attributes) == 0 {
		// The hand-written pack lists no attributes, so the plan's own value is
		// the evidence.
		after, _ := r.change.After.(map[string]any)
		_, ok := after[name]
		return ok
	}
	for _, attribute := range r.attributes {
		if attribute == name {
			return true
		}
	}
	return false
}

var camelBoundary = regexp.MustCompile(`([a-z0-9])([A-Z])`)

func snake(s string) string { return strings.ToLower(camelBoundary.ReplaceAllString(s, "${1}_${2}")) }

// pathValue is the resource's IAM path: its path attribute, or "/".
func pathValue(r plannedPermission) (string, bool) {
	if !slices.Contains(r.attributes, "path") {
		return "/", true
	}
	value, known := packs.ValueForField(r.change, "path")
	if !known {
		if packs.AttributeUnknown(r.change, "path") {
			return "", false
		}
		return "/", true
	}
	if !strings.HasSuffix(value, "/") {
		value += "/"
	}
	return value, true
}

// referencedARN finds the one known ARN among the planned values that matches a
// format: a Lambda function's role is the role it names.
func referencedARN(change model.PlannedChange, formats []string) (string, bool) {
	found := map[string]bool{}
	collectMatches(change.After, arnPatterns(formats), found)
	if len(found) != 1 {
		return "", false
	}
	for arn := range found {
		return arn, true
	}
	return "", false
}

// arnPatterns compiles each ARN format into a pattern where each variable
// matches one colon-free segment.
func arnPatterns(formats []string) []*regexp.Regexp {
	var patterns []*regexp.Regexp
	for _, format := range formats {
		pieces := formatVariable.Split(format, -1)
		for i, piece := range pieces {
			pieces[i] = regexp.QuoteMeta(piece)
		}
		if compiled, err := regexp.Compile("^" + strings.Join(pieces, `[^:]+`) + "$"); err == nil {
			patterns = append(patterns, compiled)
		}
	}
	return patterns
}

func collectMatches(value any, patterns []*regexp.Regexp, found map[string]bool) {
	switch typed := value.(type) {
	case string:
		for _, pattern := range patterns {
			if pattern.MatchString(typed) {
				found[typed] = true
			}
		}
	case map[string]any:
		for _, v := range typed {
			collectMatches(v, patterns, found)
		}
	case []any:
		for _, v := range typed {
			collectMatches(v, patterns, found)
		}
	}
}

type contextKey struct {
	Name   string
	Type   string // string or stringList
	Values []string
	// Guessed marks a value the plan does not state; a denial that may rest on
	// it is not reported as certain.
	Guessed bool
}

func contextFor(r plannedPermission, scope Scope, known map[string]iamAction) []contextKey {
	var keys []contextKey
	if scope.Region != "" {
		keys = append(keys, contextKey{Name: "aws:RequestedRegion", Type: "string", Values: []string{scope.Region}})
	}
	action := known[strings.ToLower(r.operation.Permission)]
	supports := func(name string) bool {
		for _, key := range action.ConditionKeys {
			if strings.EqualFold(key, name) {
				return true
			}
		}
		return false
	}
	if tags, ok := plannedTags(r.change); ok && (supports("aws:RequestTag/${TagKey}") || supports("aws:TagKeys")) {
		names := make([]string, 0, len(tags))
		for name, value := range tags {
			names = append(names, name)
			keys = append(keys, contextKey{Name: "aws:RequestTag/" + name, Type: "string", Values: []string{value}})
		}
		sort.Strings(names)
		keys = append(keys, contextKey{Name: "aws:TagKeys", Type: "stringList", Values: names})
		sort.Slice(keys, func(i, j int) bool { return keys[i].Name < keys[j].Name })
	}
	if strings.EqualFold(r.operation.Permission, "iam:PassRole") {
		if service, ok := passedToService(r); ok {
			keys = append(keys, contextKey{Name: "iam:PassedToService", Type: "string", Values: []string{service}, Guessed: true})
		}
	}
	return keys
}

// plannedTags is the tags the create request carries, when the plan knows all
// of them. The provider sends tags_all, which adds the provider's default_tags
// to the resource's own; tags stands in only when the plan gives no tags_all.
func plannedTags(change model.PlannedChange) (map[string]string, bool) {
	after, ok := change.After.(map[string]any)
	if !ok || packs.AttributeUnknown(change, "tags_all") {
		return nil, false
	}
	field := "tags_all"
	if after[field] == nil {
		field = "tags"
	}
	if packs.AttributeUnknown(change, field) {
		return nil, false
	}
	raw, ok := after[field].(map[string]any)
	if !ok || len(raw) == 0 {
		return nil, false
	}
	tags := map[string]string{}
	for name, value := range raw {
		text, ok := value.(string)
		if !ok {
			return nil, false
		}
		tags[name] = text
	}
	return tags, true
}

// servicePrincipals is the service a role is passed to, by the SDK service that
// creates the resource, where it differs from the service's own name.
var servicePrincipals = map[string]string{
	"sfn": "states.amazonaws.com", "cloudwatchevents": "events.amazonaws.com", "eventbridge": "events.amazonaws.com",
	"cloudwatchlogs": "logs.amazonaws.com", "configservice": "config.amazonaws.com",
}

// passedToService is the service a role is passed to: the one that creates the
// resource. It is inferred, not stated by the plan.
func passedToService(r plannedPermission) (string, bool) {
	if r.change.ResourceType == "aws_ecs_task_definition" {
		return "ecs-tasks.amazonaws.com", true
	}
	service := ""
	for _, operation := range r.siblings {
		if operation.Service != "" && !strings.EqualFold(operation.Service, "iam") {
			service = operation.Service
			break
		}
	}
	if service == "" {
		return "", false
	}
	if principal, ok := servicePrincipals[service]; ok {
		return principal, true
	}
	return service + ".amazonaws.com", true
}
