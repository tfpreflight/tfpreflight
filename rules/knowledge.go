package rules

// ResourceStatus is the trust level of a resource rule.
type ResourceStatus string

// Statuses a resource rule can carry.
const (
	StatusDiscovered  ResourceStatus = "discovered"
	StatusGenerated   ResourceStatus = "generated"
	StatusVerified    ResourceStatus = "verified"
	StatusUnsupported ResourceStatus = "unsupported"
)

// Pack is one provider version's knowledge pack.
type Pack struct {
	ServiceIdentities map[string]ServiceIdentity `json:"service_identities,omitempty"`
	SchemaVersion     int                        `json:"schema_version"`
	Provider          string                     `json:"provider"`
	TerraformSource   string                     `json:"terraform_provider"`
	ProviderVersion   string                     `json:"provider_version"`
	Resources         map[string]ResourceRule    `json:"resources"`
}

// ServiceIdentity links a provider client name to the SDK ServiceID. The SDK
// constant is authoritative, not spelling similarity to an IAM prefix.
type ServiceIdentity struct {
	ID      string `json:"id"`
	Module  string `json:"module"`
	Version string `json:"version"`
	Source  string `json:"source"`
}

// Identity is the attributes the provider says a caller must supply. Required,
// non-computed scalars are the candidates for a conflict identity.
type Identity struct {
	Fields []string `json:"fields,omitempty"`
}

// ReadLookup is the read operation the provider uses to find an existing
// resource, which makes a create conflict answerable before apply.
type ReadLookup struct {
	Operation  string `json:"operation"`
	Service    string `json:"service"`
	Resolution string `json:"resolution,omitempty"`
	// Candidates is every read operation on the read path. More than one means
	// nothing proves which answers existence.
	Candidates []string `json:"candidates,omitempty"`
	Ambiguous  bool     `json:"ambiguous,omitempty"`
}

// ResourceRule is the pack's knowledge of one Terraform resource type.
type ResourceRule struct {
	Status     ResourceStatus        `json:"status"`
	Attributes []string              `json:"attributes"`
	Identity   *Identity             `json:"identity,omitempty"`
	Lookup     *ReadLookup           `json:"lookup,omitempty"`
	Actions    map[string]ActionRule `json:"actions,omitempty"`
	Analysis   *Analysis             `json:"analysis,omitempty"`
}

// Analysis records why a discovered resource has no generated action. It is not
// authoritative.
type Analysis struct {
	RegistrationFound bool   `json:"registration_found"`
	CreateHandler     string `json:"create_handler,omitempty"`
	OperationStatus   string `json:"operation_status"`
	Reason            string `json:"reason,omitempty"`
}

// ActionRule is what one Terraform action on a resource calls and needs.
type ActionRule struct {
	APIOperations     []Operation   `json:"api_operations,omitempty"`
	Permissions       []string      `json:"permissions,omitempty"`
	PermissionDetails []Permission  `json:"permission_details,omitempty"`
	Conflict          *ConflictRule `json:"conflict,omitempty"`
	Quota             *QuotaRule    `json:"quota,omitempty"`
}

// Permission is a generated IAM requirement and how it was derived.
type Permission struct {
	Name       string `json:"permission"`
	Source     string `json:"source"`
	Service    string `json:"service"`
	Operation  string `json:"operation"`
	Confidence string `json:"confidence"`
}

// Operation is one API call an action makes, how certain the call is, and where
// in provider source it was found.
type Operation struct {
	Name       string           `json:"name"`
	Service    string           `json:"service,omitempty"`
	Certainty  string           `json:"certainty"`
	Condition  *Condition       `json:"condition,omitempty"`
	Source     *OperationSource `json:"source,omitempty"`
	Confidence string           `json:"confidence,omitempty"`
	Resolution string           `json:"resolution,omitempty"`
}

// Condition is a source-level condition. Field is empty unless the Terraform
// attribute is proven.
type Condition struct {
	Type  string `json:"type"`
	Field string `json:"field,omitempty"`
}

// OperationSource is where in provider source an operation was found.
type OperationSource struct {
	Type     string `json:"type"`
	File     string `json:"file"`
	Function string `json:"function"`
}

// ConflictRule names the conflict check for an action and the attribute that
// identifies the resource.
type ConflictRule struct {
	Type          string `json:"type"`
	IdentityField string `json:"identity_field"`
}

// QuotaRule names the quota check for an action and the planned attribute it
// reads.
type QuotaRule struct {
	Type              string `json:"type"`
	InstanceTypeField string `json:"instance_type_field"`
}
