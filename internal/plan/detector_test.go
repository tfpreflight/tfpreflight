package plan

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

func TestDetectPrefersTerraform(t *testing.T) {
	lookPath := func(binary string) (string, error) {
		return "/tools/" + binary, nil
	}
	getVersion := func(_ context.Context, path string) (string, error) {
		if path != "/tools/terraform" {
			t.Fatalf("version requested for %q", path)
		}
		return "1.9.8", nil
	}

	tool, err := detect(context.Background(), []ToolKind{Terraform, OpenTofu}, lookPath, getVersion)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if tool.Kind != Terraform || tool.Name != "Terraform" || tool.Version != "1.9.8" {
		t.Fatalf("unexpected tool: %#v", tool)
	}
}

func TestHasConfiguration(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "main.tf"), []byte("terraform {}"), 0o600); err != nil {
		t.Fatal(err)
	}
	found, err := HasConfiguration(directory)
	if err != nil || !found {
		t.Fatalf("HasConfiguration() = %v, %v; want true, nil", found, err)
	}
}

func TestHasConfigurationIgnoresNonTerraformFiles(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "notes.txt"), []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	found, err := HasConfiguration(directory)
	if err != nil || found {
		t.Fatalf("HasConfiguration() = %v, %v; want false, nil", found, err)
	}
}

func TestDetectFallsBackToOpenTofu(t *testing.T) {
	lookPath := func(binary string) (string, error) {
		if binary == "terraform" {
			return "", exec.ErrNotFound
		}
		return "/tools/tofu", nil
	}
	getVersion := func(_ context.Context, _ string) (string, error) { return "1.8.3", nil }

	tool, err := detect(context.Background(), []ToolKind{Terraform, OpenTofu}, lookPath, getVersion)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if tool.Kind != OpenTofu || tool.Name != "OpenTofu" {
		t.Fatalf("unexpected tool: %#v", tool)
	}
}

func TestDetectReturnsNotFound(t *testing.T) {
	lookPath := func(string) (string, error) { return "", exec.ErrNotFound }
	getVersion := func(context.Context, string) (string, error) {
		return "", errors.New("should not run")
	}

	_, err := detect(context.Background(), []ToolKind{Terraform, OpenTofu}, lookPath, getVersion)
	if !errors.Is(err, ErrToolNotFound) || err.Error() != "terraform or tofu executable not found: looked for terraform and tofu on PATH" {
		t.Fatalf("expected ErrToolNotFound, got %v", err)
	}
}

// A requested tool is the only one accepted, even when the other is there.
func TestDetectOnlyTheRequestedTool(t *testing.T) {
	lookPath := func(binary string) (string, error) {
		if binary == "tofu" {
			return "", exec.ErrNotFound
		}
		return "/tools/" + binary, nil
	}
	getVersion := func(context.Context, string) (string, error) { return "1.9.8", nil }
	_, err := detect(context.Background(), []ToolKind{OpenTofu}, lookPath, getVersion)
	if !errors.Is(err, ErrToolNotFound) || err.Error() != "terraform or tofu executable not found: looked for tofu on PATH" {
		t.Fatalf("err = %v, want tofu not found", err)
	}
}

func TestToolOrder(t *testing.T) {
	dir := t.TempDir()
	lock := func(name, registry string) string {
		path := filepath.Join(dir, name)
		block := `provider "` + registry + `/hashicorp/aws" {
  version = "6.64.0"
  hashes = ["h1:x"]
}
`
		if err := os.WriteFile(path, []byte(block), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	tofuLock, terraformLock := lock("tofu.hcl", "registry.opentofu.org"), lock("terraform.hcl", "registry.terraform.io")
	for name, tc := range map[string]struct {
		requested, lock string
		want            []ToolKind
		err             string
	}{
		"terraform requested": {"terraform", tofuLock, []ToolKind{Terraform}, ""},
		"tofu requested":      {"tofu", terraformLock, []ToolKind{OpenTofu}, ""},
		"unknown tool":        {"opentofu", "", nil, `tool "opentofu": must be terraform or tofu`},
		"OpenTofu lock":       {"", tofuLock, []ToolKind{OpenTofu, Terraform}, ""},
		"Terraform lock":      {"", terraformLock, []ToolKind{Terraform, OpenTofu}, ""},
		"no lock":             {"", filepath.Join(dir, "missing.hcl"), []ToolKind{Terraform, OpenTofu}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ToolOrder(tc.requested, tc.lock)
			if tc.err != "" {
				if err == nil || err.Error() != tc.err {
					t.Fatalf("err = %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("order = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestParseVersion(t *testing.T) {
	for _, test := range []struct {
		output string
		want   string
	}{
		{"Terraform v1.9.8\non darwin_arm64", "1.9.8"},
		{"OpenTofu v1.8.3", "1.8.3"},
		{"unexpected output", ""},
	} {
		if got := parseVersion(test.output); got != test.want {
			t.Errorf("parseVersion(%q) = %q, want %q", test.output, got, test.want)
		}
	}
}
