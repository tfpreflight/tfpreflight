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
		{"profile variable is described, not decided", `{"region":{"constant_value":"us-east-1"},"profile":{"references":["var.profile"]}}`, true, RegionLiteral},
		{"allowed account", `{"region":{"constant_value":"us-east-1"},"allowed_account_ids":{"constant_value":["123456789012"]}}`, true, RegionLiteral},
		// These are refused whatever they hold, a literal or a variable alike:
		// another credential chain cannot be rebuilt from the inspection
		// defaults, and a variable cannot change that.
		{"shared config files, literal", `{"region":{"constant_value":"us-east-1"},"shared_config_files":{"constant_value":["/etc/aws/config"]}}`, false, ""},
		{"shared config files, variable", `{"region":{"constant_value":"us-east-1"},"shared_config_files":{"references":["var.config_files"]}}`, false, ""},
		{"shared credentials files, variable", `{"region":{"constant_value":"us-east-1"},"shared_credentials_files":{"references":["var.credential_files"]}}`, false, ""},
		{"access key, variable", `{"region":{"constant_value":"us-east-1"},"access_key":{"references":["var.key"]}}`, false, ""},
		{"endpoints, variable", `{"region":{"constant_value":"us-east-1"},"endpoints":{"references":["var.endpoints"]}}`, false, ""},
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

// The profile is described the way the region is: Terraform records a variable
// or a local only as what it references, and the resolver decides.
func TestProviderContextDescribesTheProfile(t *testing.T) {
	for _, tc := range []struct {
		name, expressions, kind, profile string
		references                       []string
	}{
		{"not set", `{}`, ArgumentAbsent, "", nil},
		{"literal", `{"profile":{"constant_value":"prod"}}`, ArgumentLiteral, "prod", nil},
		{"variable", `{"profile":{"references":["var.aws_profile"]}}`, ArgumentReferences, "", []string{"var.aws_profile"}},
		{"local", `{"profile":{"references":["local.profile"]}}`, ArgumentReferences, "", []string{"local.profile"}},
		{"function of literals", `{"profile":{}}`, ArgumentOther, "", nil},
		{"empty literal", `{"profile":{"constant_value":""}}`, ArgumentOther, "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var doc planDocument
			if err := json.Unmarshal([]byte(`{"configuration":{"provider_config":{"aws":{"expressions":`+tc.expressions+`}}}}`), &doc); err != nil {
				t.Fatal(err)
			}
			got := providerContext(doc)
			if got.Reason != "" || got.ProfileKind != tc.kind || got.Profile != tc.profile || len(got.ProfileReferences) != len(tc.references) {
				t.Fatalf("context %+v", got)
			}
			for i, reference := range tc.references {
				if got.ProfileReferences[i] != reference {
					t.Fatalf("references %v, want %v", got.ProfileReferences, tc.references)
				}
			}
		})
	}
}

// assume_role's external ID and allowed_account_ids are described like the
// region when they reference other values, and no longer end the run.
func TestProviderContextDescribesExternalIDAndAllowedAccounts(t *testing.T) {
	var doc planDocument
	expressions := `{"region":{"constant_value":"us-east-1"},` +
		`"assume_role":[{"role_arn":{"constant_value":"arn:aws:iam::123456789012:role/deploy"},"external_id":{"references":["var.external_id"]}}],` +
		`"allowed_account_ids":{"references":["var.accounts"]}}`
	if err := json.Unmarshal([]byte(`{"configuration":{"provider_config":{"aws":{"expressions":`+expressions+`}}}}`), &doc); err != nil {
		t.Fatal(err)
	}
	got := providerContext(doc)
	if got.Reason != "" || got.AssumeRole == nil || got.AssumeRole.Unresolved != "" || got.AssumeRole.ExternalID != "" ||
		len(got.AssumeRole.ExternalIDReferences) != 1 || got.AssumeRole.ExternalIDReferences[0] != "var.external_id" ||
		len(got.AllowedAccounts) != 0 || len(got.AllowedAccountsReferences) != 1 || got.AllowedAccountsReferences[0] != "var.accounts" {
		t.Fatalf("context %+v, assume_role %+v", got, got.AssumeRole)
	}
	// Neither a function of literals nor anything else with no value or
	// references can be resolved.
	for _, tc := range []string{
		`{"region":{"constant_value":"us-east-1"},"allowed_account_ids":{}}`,
		`{"region":{"constant_value":"us-east-1"},"assume_role":[{"role_arn":{"constant_value":"arn:aws:iam::123456789012:role/deploy"},"external_id":{}}]}`,
	} {
		var doc planDocument
		if err := json.Unmarshal([]byte(`{"configuration":{"provider_config":{"aws":{"expressions":`+tc+`}}}}`), &doc); err != nil {
			t.Fatal(err)
		}
		got := providerContext(doc)
		if got.Reason == "" && (got.AssumeRole == nil || got.AssumeRole.Unresolved == "") {
			t.Errorf("%s was taken as resolvable: %+v", tc, got)
		}
	}
}
