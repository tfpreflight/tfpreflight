package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

func TestSupportBundleRedactsSensitiveResultFields(t *testing.T) {
	document := Document{
		SchemaVersion: "1",
		Provider:      ProviderInfo{Version: "6.64.0", Mode: "COVERED", RulesVersion: "6.64.0"},
		Findings: []Finding{{
			ID: "dependency", Resource: "aws_s3_bucket.secret_name", Category: "dependency",
			Severity: model.SeverityWarning, Message: "bucket customer-secret is missing", Reason: "arn:aws:s3:::customer-secret in account 111122223333",
		}},
		Coverage: []ResourceCoverage{{
			Resource: "aws_s3_bucket.secret_name", Status: "partial",
			Checks: map[string]model.CheckStatus{"dependencies": model.CheckPartialDependency}, Reasons: []string{"customer-secret was unavailable"},
		}},
		AWSContext: &AWSContextInfo{ApplyIdentity: "arn:aws:iam::111122223333:role/deploy"},
		Error:      "/private/project/customer-secret.tfplan",
	}
	bundle := NewBundle(document, "v0.1.0", "abc123", "embedded", false)
	data, err := MarshalBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret_name", "customer-secret", "111122223333", "arn:aws", ".tfplan"} {
		if bytes.Contains(data, []byte(secret)) {
			t.Errorf("redacted bundle contains %q:\n%s", secret, data)
		}
	}
	for _, want := range []string{`"pack_id": "embedded"`, `"mode": "COVERED"`, `"resource": "resource-001"`, `"message": "[redacted]"`, `"sensitive_values_included": false`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("bundle lacks %s:\n%s", want, data)
		}
	}
}

func TestSupportBundleIncludesFullDocumentOnlyWhenRequested(t *testing.T) {
	document := Document{Findings: []Finding{{Resource: "aws_s3_bucket.named", Message: "named"}}}
	bundle := NewBundle(document, "dev", "unknown", "embedded", true)
	if !bundle.Redaction.SensitiveValuesIncluded || len(bundle.Redaction.Excluded) != 0 {
		t.Fatalf("redaction metadata = %+v", bundle.Redaction)
	}
	if got := bundle.Report.Findings[0]; got.Resource != "aws_s3_bucket.named" || got.Message != "named" {
		t.Fatalf("full finding = %+v", got)
	}
}
