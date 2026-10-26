package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// SemanticFingerprint identifies only facts that can change a quota answer.
// IAM permissions and explanatory evidence are intentionally absent.
func SemanticFingerprint(rule Rule) string {
	identity := struct {
		Resource    string
		ServiceCode string
		QuotaCode   string
		Scope       string
		Consumption Consumption
		Metric      *UsageMetric
		Counter     *UsageCounter
	}{rule.Resource, rule.ServiceCode, rule.QuotaCode, rule.Scope, rule.Consumption, rule.Usage, rule.Counter}
	data, _ := json.Marshal(identity)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
