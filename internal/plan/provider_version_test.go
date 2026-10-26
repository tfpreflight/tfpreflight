package plan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAWSProviderVersion(t *testing.T) {
	block := `provider "registry.terraform.io/hashicorp/aws" { version = "6.64.0" }`
	tests := []struct {
		name, contents string
		valid          bool
	}{
		{"exact", block, true},
		{"OpenTofu registry", strings.Replace(block, "registry.terraform.io", "registry.opentofu.org", 1), true},
		{"hash comment", "# provider \"registry.terraform.io/hashicorp/aws\"\n" + block, true},
		{"block comment", "/* " + block + " */\n" + block, true},
		{"duplicate block", block + block, false},
		{"duplicate version", `provider "registry.terraform.io/hashicorp/aws" { version = "6.64.0" version = "6.65.0" }`, false},
		{"unterminated", `provider "registry.terraform.io/hashicorp/aws" { version = "6.64.0"`, false},
		{"expression", `provider "registry.terraform.io/hashicorp/aws" { version = var.version }`, false},
		{"missing", "", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), ".terraform.lock.hcl")
			if err := os.WriteFile(path, []byte(test.contents), 0o600); err != nil {
				t.Fatal(err)
			}
			version, err := AWSProviderVersion(path)
			if (err == nil) != test.valid || test.valid && version != "6.64.0" {
				t.Fatalf("version=%q error=%v", version, err)
			}
		})
	}
}
