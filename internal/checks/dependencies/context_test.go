package dependencies

import (
	"encoding/json"
	"testing"
)

func TestProviderContextRequiresProvenExpressions(t *testing.T) {
	for _, tc := range []struct {
		name, expressions string
		known             bool
		regionKind        string
	}{
		{"literal", `{"region":{"constant_value":"us-east-1"}}`, true, RegionLiteral},
		{"missing", `{}`, true, RegionAbsent},
		{"variable is described, not decided", `{"region":{"references":["var.region"]}}`, true, RegionReferences},
		{"function of literals", `{"region":{}}`, true, RegionOther},
		{"role is read, not refused", `{"region":{"constant_value":"us-east-1"},"assume_role":[{"role_arn":{"constant_value":"arn:aws:iam::123456789012:role/deploy"}}]}`, true, RegionLiteral},
		{"web identity role", `{"region":{"constant_value":"us-east-1"},"assume_role_with_web_identity":{}}`, false, ""},
		{"custom endpoint", `{"region":{"constant_value":"us-east-1"},"endpoints":{}}`, false, ""},
		{"unknown profile", `{"region":{"constant_value":"us-east-1"},"profile":{"references":["var.profile"]}}`, false, RegionLiteral},
		{"allowed account", `{"region":{"constant_value":"us-east-1"},"allowed_account_ids":{"constant_value":["123456789012"]}}`, true, RegionLiteral},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var doc planDocument
			if err := json.Unmarshal([]byte(`{"variables":{"region":{"value":"us-east-1"}},"configuration":{"provider_config":{"aws":{"expressions":`+tc.expressions+`}}}}`), &doc); err != nil {
				t.Fatal(err)
			}
			got := providerContext(doc)
			if (got.Reason == "") != tc.known || got.RegionKind != tc.regionKind {
				t.Fatalf("context %+v", got)
			}
			if tc.name == "role is read, not refused" && (got.AssumeRole == nil || got.AssumeRole.RoleARN != "arn:aws:iam::123456789012:role/deploy") {
				t.Fatalf("assume_role %+v", got.AssumeRole)
			}
			if got.Variables["region"] != "us-east-1" {
				t.Fatalf("plan variables not carried: %+v", got.Variables)
			}
		})
	}
}
