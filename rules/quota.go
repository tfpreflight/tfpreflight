// The schema of the quota packs: the rule the runtime quota engine reads, with
// the two predicates that are part of a rule's meaning.

package rules

// Scope is what an AWS quota is counted against. Comparing a regional usage
// figure with a global limit, or an account total with a per-VPC limit, would
// give a confident wrong answer, so the scope travels with the quota.
const (
	ScopeRegion  = "region"
	ScopeAccount = "account"
	ScopeGlobal  = "global"
	ScopeAZ      = "availability-zone"
	ScopeVPC     = "vpc"
	ScopeParent  = "resource-parent"
)

// Consumption families: how much of a quota one planned resource uses. A family
// exists only when its arithmetic holds for every resource in it.
const (
	// ConsumptionResourceCount is one unit per resource, as for "VPCs per
	// Region".
	ConsumptionResourceCount = "resource-count"
	// ConsumptionVCPU derives units from an instance type's vCPU count, which
	// DescribeInstanceTypes reports.
	ConsumptionVCPU = "vcpu-derived"
	// ConsumptionAttribute reads the unit count from a planned attribute.
	ConsumptionAttribute = "attribute-derived"
	// ConsumptionUnknown means the resource consumes the quota by an unknown
	// amount. It is not a zero.
	ConsumptionUnknown = "unknown"
)

// Consumption is how a resource draws on a quota.
type Consumption struct {
	Type string `json:"type"`
	// Field is the planned attribute read for attribute-derived and vCPU-derived
	// consumption.
	Field string `json:"field,omitempty"`
	// Units is the fixed count for resource-count consumption.
	Units float64 `json:"units,omitempty"`
}

// UsageMetric is the CloudWatch metric AWS publishes for a quota. Any quota that
// has one is measured with the same CloudWatch call, with no per-service code.
type UsageMetric struct {
	Namespace  string            `json:"namespace"`
	MetricName string            `json:"metric_name"`
	Dimensions map[string]string `json:"dimensions"`
	Statistic  string            `json:"statistic"`
}

// UsageCounter measures usage by listing the resources AWS returns, through a
// generated SDK adapter. It only describes the call: the quota engine makes
// every decision.
type UsageCounter struct {
	Adapter    string `json:"adapter"`
	Operation  string `json:"operation"`
	Collection string `json:"collection"`
	Pagination string `json:"pagination"` // none, paginator, or token-loop
}

// Rule is the quota knowledge for one Terraform resource.
type Rule struct {
	Resource    string        `json:"resource"`
	ServiceCode string        `json:"service_code"`
	QuotaCode   string        `json:"quota_code"`
	QuotaName   string        `json:"quota_name,omitempty"`
	Scope       string        `json:"scope"`
	Adjustable  bool          `json:"adjustable"`
	Consumption Consumption   `json:"consumption"`
	Usage       *UsageMetric  `json:"usage_metric,omitempty"`
	Counter     *UsageCounter `json:"usage_counter,omitempty"`
	// Evidence is where the association came from, so an inferred rule is never
	// taken for something AWS stated.
	Evidence        string `json:"evidence"`
	MappingEvidence string `json:"mapping_evidence,omitempty"`
	UsageEvidence   string `json:"usage_evidence,omitempty"`
	ScopeEvidence   string `json:"scope_evidence,omitempty"`
	// Trust is verified only when the resource, units and scope are established
	// independently of name similarity.
	Trust string `json:"trust,omitempty"`
	// Fingerprint identifies the quota's semantics when a rule is carried to a
	// new version. It excludes IAM permissions.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// BlockingSafe is stricter than Computable: a sound counter is not enough to
// block an apply unless the quota's semantics are verified.
func (r Rule) BlockingSafe() bool {
	return r.Trust == TrustVerified && r.MappingEvidence != "" && r.UsageEvidence != "" && r.ScopeEvidence != ""
}

// Computable reports whether a rule can reach a verdict: a quota to look up, a
// way to measure current usage, and arithmetic for what the plan adds.
func (r Rule) Computable() bool {
	return r.QuotaCode != "" && (r.Usage != nil || r.Counter != nil) && r.Consumption.Type != ConsumptionUnknown && r.Consumption.Type != ""
}
