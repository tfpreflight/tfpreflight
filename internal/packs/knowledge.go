package packs

import (
	"encoding/json"
	"fmt"
	"strings"

	generated "github.com/tfpreflight/tfpreflight/rules"
	"github.com/tfpreflight/tfpreflight/rules/model"
)

// A shipped pack has exactly one copy, under packs/, read through the embed
// package.
func packFile(path string) ([]byte, error) { return ReadFile(path) }

func defaultPack() []byte {
	data, _ := packFile("aws/knowledge/v1.json")
	return data
}

// Certainty is whether an action always makes an API call. Trust, separately, is
// how well the permission it needs is established.
const (
	CertaintyRequired    = "required"
	CertaintyConditional = "conditional"
	// CertaintyUnknown is an operation found in provider source without knowing
	// whether the call is conditional. It is still simulated, at generated
	// trust: treating it as conditional would discard most of the generated
	// pack.
	CertaintyUnknown = "unknown"
)

// KnowledgePack describes the AWS resources tfpreflight supports.
type KnowledgePack struct {
	ServiceIdentities map[string]generated.ServiceIdentity `json:"service_identities,omitempty"`
	SchemaVersion     int                                  `json:"schema_version"`
	Provider          string                               `json:"provider"`
	TerraformProvider string                               `json:"terraform_provider"`
	ProviderVersion   string                               `json:"provider_version"`
	Resources         map[string]ResourceRule              `json:"resources"`
}

// ResourceRule is the pack's knowledge of one Terraform resource type, keyed by
// action.
type ResourceRule struct {
	ResourceLabel string                `json:"resource_label"`
	Trust         string                `json:"trust"`
	Actions       map[string]ActionRule `json:"actions"`
	// IdentityFields name the resource, and Attributes are all of its
	// attributes; the permission check builds the resource's ARN from them.
	IdentityFields []string `json:"identity_fields,omitempty"`
	Attributes     []string `json:"attributes,omitempty"`
}

// ActionRule lists the API operations one Terraform action performs, and the
// conflict and quota checks for it.
type ActionRule struct {
	OperationLabel string          `json:"operation_label"`
	Operations     []OperationRule `json:"operations"`
	Conflict       *ConflictRule   `json:"conflict"`
	Quota          *QuotaRule      `json:"quota"`
}

// OperationRule is one API operation and the IAM permission it needs.
type OperationRule struct {
	Service    string `json:"service,omitempty"`
	Name       string `json:"name"`
	Permission string `json:"permission"`
	Certainty  string `json:"certainty"`
	Trust      string `json:"trust"`
	// Condition lets a conditional operation be required when the plan satisfies
	// it.
	Condition *OperationCondition `json:"condition,omitempty"`
}

// OperationCondition is a condition a planned change can be tested against.
type OperationCondition struct {
	Type  string `json:"type"`
	Field string `json:"field,omitempty"`
	// Equals is, for ConditionAnyEquals, each field and the value that makes
	// the operation run.
	Equals map[string]any `json:"equals,omitempty"`
}

// Condition types.
const (
	// ConditionAttributeSet is satisfied when the planned resource sets a
	// non-empty value for the field.
	ConditionAttributeSet = "attribute-set"
	// ConditionAnyEquals is satisfied when any field in Equals has its value,
	// or is unknown until apply.
	ConditionAnyEquals = "any-equals"
)

// ConditionEvaluable reports whether the plan can decide if this operation runs.
func (o OperationRule) ConditionEvaluable() bool {
	if o.Certainty != CertaintyConditional {
		return true
	}
	switch {
	case o.Condition == nil:
		return false
	case o.Condition.Type == ConditionAttributeSet:
		return o.Condition.Field != ""
	case o.Condition.Type == ConditionAnyEquals:
		return len(o.Condition.Equals) > 0
	}
	return false
}

// WillRun reports whether the apply performs this operation, as far as the plan
// can say. An operation of unknown certainty counts as running: assuming
// otherwise could drop a needed permission. Callers must check
// ConditionEvaluable first; for an operation it rejects, the answer here is not
// a decision.
func (o OperationRule) WillRun(change model.PlannedChange) bool {
	if o.Certainty != CertaintyConditional {
		return true
	}
	if !o.ConditionEvaluable() {
		return false
	}
	if o.Condition.Type == ConditionAnyEquals {
		return anyAttributeEquals(change, o.Condition.Equals)
	}
	return attributeIsSet(change, o.Condition.Field)
}

// An unknown value counts as equal, for the same reason it counts as set.
func anyAttributeEquals(change model.PlannedChange, equals map[string]any) bool {
	after, _ := change.After.(map[string]any)
	for field, want := range equals {
		if attributeUnknown(change.AfterUnknown, field) || after[field] == want {
			return true
		}
	}
	return false
}

// Required reports whether an operation's permission should be checked for a
// change: the apply performs it and its authorization is known. Tagging is the
// usual case: AWS requires the tagging permission only when the create request
// carries tags.
func (o OperationRule) Required(change model.PlannedChange) bool {
	return o.Permission != "" && o.WillRun(change)
}

// AlwaysRuns reports whether the rule says the provider makes this call every
// time the action runs. The generated pack says so with "required"; the
// hand-written pack sets no certainty and lists only such calls.
func (o OperationRule) AlwaysRuns() bool {
	return o.Certainty == CertaintyRequired || o.Certainty == ""
}

// An unknown value counts as set: the apply will send whatever it resolves to.
func attributeIsSet(change model.PlannedChange, field string) bool {
	if attributeUnknown(change.AfterUnknown, field) {
		return true
	}
	after, ok := change.After.(map[string]any)
	if !ok {
		return false
	}
	switch value := after[field].(type) {
	case nil:
		return false
	case string:
		return value != ""
	case map[string]any:
		return len(value) > 0
	case []any:
		return len(value) > 0
	default:
		return true
	}
}

// LoadRuntimePack loads the knowledge for exactly the provider version Terraform
// selected: the generated pack with the verified evidence over it. There is no
// nearest-version fallback. A provider release can change which API a resource
// calls, so another version's knowledge would give confident findings about
// behaviour that no longer exists. When the version is not shipped, the caller
// reports the provider as unsupported.
func LoadRuntimePack(version string) (KnowledgePack, bool, error) {
	if version == "" {
		return KnowledgePack{}, false, nil
	}
	path := "aws/generated/aws-" + version + ".json"
	data, err := packFile(path)
	if err != nil {
		return KnowledgePack{}, false, nil
	}
	var source generated.Pack
	if err := json.Unmarshal(data, &source); err != nil {
		return KnowledgePack{}, false, fmt.Errorf("parse generated AWS knowledge pack: %w", err)
	}
	if source.Provider != "aws" || source.ProviderVersion != version {
		return KnowledgePack{}, false, nil
	}
	pack, err := loadDefaultPack()
	if err != nil {
		return KnowledgePack{}, false, err
	}
	pack.ServiceIdentities = source.ServiceIdentities
	for resourceType, sourceRule := range source.Resources {
		if rule, ok := generatedResource(resourceType, sourceRule); ok {
			pack.Resources[resourceType] = rule
		}
	}
	if err := applyVerifiedEvidence(&pack, version); err != nil {
		return pack, false, err
	}
	applyBuiltinConflictRules(&pack)
	applyReviewedConditions(&pack)
	return pack, true, nil
}

// These rules describe lookups, not permissions: GetRole proves an account-
// scoped role name is taken, and S3 bucket names are global. Only types the
// generated conflict resolver does not cover belong here; a type in both would
// be reported twice.
func applyBuiltinConflictRules(pack *KnowledgePack) {
	for resourceName, definition := range map[string]ConflictRule{
		"aws_s3_bucket": {Type: "s3_bucket_exists", IdentityField: "bucket"},
		"aws_iam_role":  {Type: "iam_name_exists", IdentityField: "name"},
	} {
		resource, found := pack.Resources[resourceName]
		if !found {
			resource = ResourceRule{ResourceLabel: resourceName, Trust: "generated", Actions: map[string]ActionRule{}}
		}
		action, found := resource.Actions["create"]
		if !found {
			action = ActionRule{OperationLabel: "Create"}
		}
		action.Conflict = &definition
		resource.Actions["create"] = action
		pack.Resources[resourceName] = resource
	}
}

// generatedResource converts one generated resource rule, or reports false when
// it is not generated or has no action with an operation.
func generatedResource(resourceType string, source generated.ResourceRule) (ResourceRule, bool) {
	if source.Status != generated.StatusGenerated {
		return ResourceRule{}, false
	}
	rule := ResourceRule{ResourceLabel: resourceType, Trust: "generated", Actions: map[string]ActionRule{}, Attributes: source.Attributes}
	if source.Identity != nil {
		rule.IdentityFields = source.Identity.Fields
	}
	for actionName, sourceAction := range source.Actions {
		if action := generatedAction(sourceAction); len(action.Operations) > 0 {
			rule.Actions[actionName] = action
		}
	}
	return rule, len(rule.Actions) > 0
}

// generatedAction converts every API operation of one generated action. An
// operation whose authorization is unknown, or that is conditional, is kept
// rather than dropped: dropping it would make an incomplete permission result
// look complete.
func generatedAction(source generated.ActionRule) ActionRule {
	action := ActionRule{OperationLabel: "Create", Operations: make([]OperationRule, 0)}
	permissions := map[string]bool{}
	for _, permission := range source.Permissions {
		permissions[permission] = true
	}
	for _, operation := range source.APIOperations {
		permission := operationPermission(operation, source.PermissionDetails, permissions)
		if !permissions[permission] {
			permission = ""
		}
		action.Operations = append(action.Operations, generatedOperation(operation, permission))
	}
	return action
}

// operationPermission is the matching permission detail when the action lists
// it, else service:name.
func operationPermission(operation generated.Operation, details []generated.Permission, permissions map[string]bool) string {
	for _, detail := range details {
		if detail.Service == operation.Service && detail.Operation == operation.Name && permissions[detail.Name] {
			return detail.Name
		}
	}
	return operation.Service + ":" + operation.Name
}

func generatedOperation(operation generated.Operation, permission string) OperationRule {
	certainty := operation.Certainty
	if certainty == "" {
		certainty = CertaintyUnknown
	}
	rule := OperationRule{Service: operation.Service, Name: operation.Name, Permission: permission, Certainty: certainty, Trust: "generated"}
	if operation.Condition != nil {
		rule.Condition = &OperationCondition{Type: operation.Condition.Type, Field: operation.Condition.Field}
	}
	return rule
}

// applyVerifiedEvidence raises to verified trust only the exact evidence
// tuples recorded for this version: Terraform resource, create action and IAM
// permission. It cannot promote a whole service or version.
func applyVerifiedEvidence(pack *KnowledgePack, version string) error {
	data, err := packFile("aws/generated/verified-aws-" + version + ".json")
	if err != nil {
		return nil // no evidence overlay is a supported partial-coverage state
	}
	var evidence struct {
		ProviderVersion string                         `json:"provider_version"`
		Resources       map[string]map[string][]string `json:"resources"`
	}
	if err := json.Unmarshal(data, &evidence); err != nil {
		return fmt.Errorf("parse verified AWS evidence overlay: %w", err)
	}
	if evidence.ProviderVersion != version {
		return fmt.Errorf("verified evidence overlay version %q does not match %q", evidence.ProviderVersion, version)
	}
	for resourceName, actions := range evidence.Resources {
		if resource, found := pack.Resources[resourceName]; found {
			markVerified(resource, actions)
			pack.Resources[resourceName] = resource
		}
	}
	return nil
}

func markVerified(resource ResourceRule, actions map[string][]string) {
	for actionName, permissions := range actions {
		action, found := resource.Actions[actionName]
		if !found {
			continue
		}
		verified := map[string]bool{}
		for _, permission := range permissions {
			verified[permission] = true
		}
		for i := range action.Operations {
			if verified[action.Operations[i].Permission] {
				action.Operations[i].Trust = "verified"
			}
		}
		resource.Actions[actionName] = action
	}
}

// ConflictRule names the conflict check for an action and the attribute that
// identifies the resource.
type ConflictRule struct {
	Type          string `json:"type"`
	IdentityField string `json:"identity_field"`
}

// QuotaRule names the quota check for an action and the planned attributes it
// reads.
type QuotaRule struct {
	Type               string `json:"type"`
	InstanceTypeField  string `json:"instance_type_field"`
	RegionField        string `json:"region_field"`
	InstanceTypePrefix string `json:"instance_type_prefix"`
}

// ResolvedRule connects a planned change to one action rule from the knowledge
// pack.
type ResolvedRule struct {
	Change         model.PlannedChange
	ResourceLabel  string
	Action         ActionRule
	IdentityFields []string
	Attributes     []string
}

func loadDefaultPack() (KnowledgePack, error) {
	var pack KnowledgePack
	if err := json.Unmarshal(defaultPack(), &pack); err != nil {
		return KnowledgePack{}, fmt.Errorf("parse embedded AWS knowledge pack: %w", err)
	}
	if pack.SchemaVersion != 1 || pack.Provider != "aws" {
		return KnowledgePack{}, fmt.Errorf("unsupported AWS knowledge pack")
	}
	return pack, nil
}

// ResolveRules matches each AWS planned change to the pack's rule for its
// resource type and action, leaving out changes it has no rule for. A create
// also gets the read operations, because apply refreshes a resource right after
// creating it.
func ResolveRules(pack KnowledgePack, changes []model.PlannedChange) []ResolvedRule {
	resolved := make([]ResolvedRule, 0)
	for _, change := range changes {
		if model.NormalizeProvider(change.ProviderName) != model.ProviderAWS {
			continue
		}
		resource, found := pack.Resources[change.ResourceType]
		if !found {
			continue
		}
		action, found := resource.Actions[string(change.Action)]
		if !found {
			continue
		}
		if change.Action == model.ActionCreate {
			action = withReadAfterCreate(action, resource.Actions["read"])
		}
		resolved = append(resolved, ResolvedRule{Change: change, ResourceLabel: resource.ResourceLabel, Action: action, IdentityFields: resource.IdentityFields, Attributes: resource.Attributes})
	}
	return resolved
}

// withReadAfterCreate appends the read operations to a create: apply refreshes a
// resource right after creating it, so an identity with only the create
// permissions cannot finish. They are appended, not merged, so each keeps its
// provenance; duplicates are dropped, since some resources read with the
// operation they create with.
func withReadAfterCreate(create, read ActionRule) ActionRule {
	if len(read.Operations) == 0 {
		return create
	}
	seen := make(map[string]bool, len(create.Operations))
	for _, operation := range create.Operations {
		seen[strings.ToLower(operation.Permission)] = true
	}
	for _, operation := range read.Operations {
		if operation.Permission == "" || seen[strings.ToLower(operation.Permission)] {
			continue
		}
		seen[strings.ToLower(operation.Permission)] = true
		create.Operations = append(create.Operations, operation)
	}
	return create
}

// ValueForField returns a planned attribute's string value. It reports false
// when the value is unknown until apply, absent, empty, or not a string.
func ValueForField(change model.PlannedChange, field string) (string, bool) {
	if attributeUnknown(change.AfterUnknown, field) {
		return "", false
	}
	after, ok := change.After.(map[string]any)
	if !ok {
		return "", false
	}
	value, ok := after[field].(string)
	return value, ok && value != ""
}

// AttributeUnknown reports whether a planned attribute is unknown until apply.
func AttributeUnknown(change model.PlannedChange, field string) bool {
	return attributeUnknown(change.AfterUnknown, field)
}

// SupportedVersions lists the provider versions this binary declares support
// for, from the one support manifest in the embedded packs. A test checks it
// against the packs actually present.
func SupportedVersions() (map[string][]string, error) {
	declared, err := AWS()
	if err != nil {
		return nil, err
	}
	return map[string][]string{"aws": declared}, nil
}

// EmbeddedPackVersions lists the AWS provider versions present in the embedded
// packs.
func EmbeddedPackVersions() ([]string, error) {
	set, err := Active()
	if err != nil {
		return nil, err
	}
	return set.Versions(), nil
}

func attributeUnknown(afterUnknown any, field string) bool {
	unknown, ok := afterUnknown.(map[string]any)
	if !ok {
		return false
	}
	value, present := unknown[field]
	if !present {
		return false
	}
	flag, ok := value.(bool)
	return ok && flag
}
