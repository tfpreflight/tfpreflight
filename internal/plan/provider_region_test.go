package plan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRegionVariableAcceptsOnlyABareVariable(t *testing.T) {
	for name, tc := range map[string]struct {
		files   map[string]string
		want    string
		ok      bool
		failure bool
	}{
		"bare variable":           {files: map[string]string{"main.tf": "provider \"aws\" {\n  region = var.region\n}\n"}, want: "region", ok: true},
		"other variable name":     {files: map[string]string{"providers.tf": "provider \"aws\" {\n  region = var.target\n}\n"}, want: "target", ok: true},
		"function":                {files: map[string]string{"main.tf": "provider \"aws\" {\n  region = format(\"%s\", var.region)\n}\n"}},
		"attribute of a variable": {files: map[string]string{"main.tf": "provider \"aws\" {\n  region = var.settings.region\n}\n"}},
		"local":                   {files: map[string]string{"main.tf": "provider \"aws\" {\n  region = local.region\n}\n"}},
		"no region":               {files: map[string]string{"main.tf": "provider \"aws\" {}\n"}},
		"no provider block":       {files: map[string]string{"main.tf": "resource \"aws_vpc\" \"x\" {}\n"}},
		// An aliased provider is not the default one resources use.
		"alias ignored": {files: map[string]string{"main.tf": "provider \"aws\" {\n  alias  = \"west\"\n  region = var.other\n}\nprovider \"aws\" {\n  region = var.region\n}\n"}, want: "region", ok: true},
		"override file": {files: map[string]string{"main.tf": "provider \"aws\" {\n  region = var.region\n}\n", "provider_override.tf": "provider \"aws\" {\n  region = \"us-east-1\"\n}\n"}, failure: true},
		"unparseable":   {files: map[string]string{"main.tf": "provider \"aws\" {\n"}, failure: true},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for file, content := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, ok, err := RegionVariable(dir)
			if (err != nil) != tc.failure || ok != tc.ok || got != tc.want {
				t.Fatalf("RegionVariable = %q, %v, %v; want %q, %v, failure %v", got, ok, err, tc.want, tc.ok, tc.failure)
			}
		})
	}
}

func TestAssumeRoleVariableReadsTheNestedBlock(t *testing.T) {
	for name, tc := range map[string]struct {
		content string
		want    string
		ok      bool
	}{
		"bare variable": {content: "provider \"aws\" {\n  assume_role {\n    role_arn = var.deploy_role\n  }\n}\n", want: "deploy_role", ok: true},
		"literal":       {content: "provider \"aws\" {\n  assume_role {\n    role_arn = \"arn:aws:iam::123456789012:role/deploy\"\n  }\n}\n"},
		"interpolated":  {content: "provider \"aws\" {\n  assume_role {\n    role_arn = \"arn:aws:iam::${var.account}:role/deploy\"\n  }\n}\n"},
		"no block":      {content: "provider \"aws\" {\n  region = var.region\n}\n"},
		// role_arn outside the assume_role block is not the role.
		"top-level only": {content: "provider \"aws\" {\n  role_arn = var.x\n}\n"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			got, ok, err := AssumeRoleVariable(dir)
			if err != nil || ok != tc.ok || got != tc.want {
				t.Fatalf("AssumeRoleVariable = %q, %v, %v; want %q, %v", got, ok, err, tc.want, tc.ok)
			}
		})
	}
}

func TestRegionLocalAcceptsOnlyAPlainString(t *testing.T) {
	const provider = "provider \"aws\" {\n  region = local.region\n}\n"
	for name, tc := range map[string]struct {
		files   map[string]string
		want    string
		ok      bool
		failure bool
	}{
		"plain string":            {files: map[string]string{"main.tf": provider + "locals {\n  region = \"eu-west-1\"\n}\n"}, want: "eu-west-1", ok: true},
		"defined in another file": {files: map[string]string{"main.tf": provider, "locals.tf": "locals {\n  name   = \"x\"\n  region = \"us-east-2\"\n}\n"}, want: "us-east-2", ok: true},
		"template without values": {files: map[string]string{"main.tf": provider + "locals {\n  region = \"eu-${\"west\"}-1\"\n}\n"}, want: "eu-west-1", ok: true},
		"from a variable":         {files: map[string]string{"main.tf": provider + "locals {\n  region = var.region\n}\n"}},
		"interpolated":            {files: map[string]string{"main.tf": provider + "locals {\n  region = \"eu-${var.side}-1\"\n}\n"}},
		"function":                {files: map[string]string{"main.tf": provider + "locals {\n  region = lower(\"EU-WEST-1\")\n}\n"}},
		"not a string":            {files: map[string]string{"main.tf": provider + "locals {\n  region = 1\n}\n"}},
		"empty":                   {files: map[string]string{"main.tf": provider + "locals {\n  region = \"\"\n}\n"}},
		"defined twice":           {files: map[string]string{"main.tf": provider + "locals {\n  region = \"eu-west-1\"\n}\nlocals {\n  region = \"eu-west-2\"\n}\n"}},
		"never defined":           {files: map[string]string{"main.tf": provider}},
		"local of a local":        {files: map[string]string{"main.tf": "provider \"aws\" {\n  region = local.settings.region\n}\nlocals {\n  settings = { region = \"eu-west-1\" }\n}\n"}},
		"function of the local":   {files: map[string]string{"main.tf": "provider \"aws\" {\n  region = lower(local.region)\n}\nlocals {\n  region = \"eu-west-1\"\n}\n"}},
		"override file":           {files: map[string]string{"main.tf": provider + "locals {\n  region = \"eu-west-1\"\n}\n", "override.tf": "locals {\n  region = \"us-east-1\"\n}\n"}, failure: true},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for file, content := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, got, ok, err := RegionLocal(dir)
			if (err != nil) != tc.failure || ok != tc.ok || got != tc.want {
				t.Fatalf("RegionLocal = %q, %v, %v; want %q, %v, failure %v", got, ok, err, tc.want, tc.ok, tc.failure)
			}
		})
	}
}
