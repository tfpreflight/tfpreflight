package aws

import (
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/tfpreflight/tfpreflight/internal/checks/quotas"
	"github.com/tfpreflight/tfpreflight/internal/checks/quotas/counters"
)

const testProviderVersion = "6.64.0"

// This test needs both the quota rules and the counter adapters, so it lives
// where the two are wired together rather than inside either package.
func TestEveryGeneratedCounterRuleHasAnAdapter(t *testing.T) {
	rules, loaded, err := quotas.LoadQuotaRules(testProviderVersion)
	if err != nil || !loaded {
		t.Fatalf("load quota rules: loaded=%v err=%v", loaded, err)
	}
	registry := counters.NewRegistry()
	counters.RegisterGenerated(registry, awssdk.Config{})
	for _, rule := range rules {
		if rule.Counter != nil && !registry.Has(rule.Counter.Adapter) {
			t.Fatalf("%s uses generated counter %q with no registered adapter", rule.Resource, rule.Counter.Adapter)
		}
	}
	if _, duplicate := rules["aws_instance"]; duplicate {
		t.Fatal("generated quota rules must not duplicate the authoritative verified EC2 vCPU checker")
	}
}
