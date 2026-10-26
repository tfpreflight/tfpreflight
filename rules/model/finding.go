package model

// Severity communicates the impact of a preflight finding.
type Severity string

// Severities, from least to most severe.
const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

// Confidence communicates how certain tfpreflight is about a finding.
type Confidence string

// Confidence levels, from least to most certain.
const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// Finding is a provider-independent result produced by a preflight check.
type Finding struct {
	ID                  string
	Provider            string
	Resource            string
	Category            string
	Severity            Severity
	Confidence          Confidence
	Title               string
	Details             []Detail
	Operation           string
	Problem             string
	Permission          string
	Principal           string
	Decision            string
	DecisionExplanation string
	Explanation         string
	Remediation         string
	Notes               []string
	Reason              string
	// Brief is the finding in one plain sentence naming its key value, such as
	// a bucket name or an IAM action, and Next the one line after it, starting
	// "Fix:" or "Check:". The default text output shows only these, and keeps
	// only the resource part of any ARN in them, so it names no account.
	Brief string
	Next  string
	// AWSError is set on a finding that reports an AWS call that got no answer:
	// what went wrong.
	AWSError string
	// Gaps make the finding a coverage note: what a check could not cover, not
	// a predicted problem.
	Gaps []Gap
}

// Gap is one thing a check could not cover for a resource: Summary in a few
// words, and Why, the reason gaps of its kind happen, which the text output
// states once for all resources.
type Gap struct {
	Summary string
	Why     string
}

// Findings is a list of normalized preflight findings.
type Findings []Finding

// Detail is an optional labeled value providing evidence for a finding.
type Detail struct {
	Label string
	Value string
}
