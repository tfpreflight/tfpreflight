package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDocumentedCosignIdentityMatchesReleaseWorkflow(t *testing.T) {
	const (
		repository   = "tfpreflight/tfpreflight"
		workflowPath = ".github/workflows/release.yml"
		oidcIssuer   = "https://token.actions.githubusercontent.com"
	)

	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(workflowPath))); err != nil {
		t.Fatalf("release workflow %q: %v", workflowPath, err)
	}
	documentation, err := os.ReadFile(filepath.Join(root, "docs", "install.md"))
	if err != nil {
		t.Fatal(err)
	}

	wantIdentity := "^https://github.com/" + repository + "/" + workflowPath + "@refs/tags/v"
	for name, want := range map[string]string{
		"certificate identity": wantIdentity,
		"OIDC issuer":          oidcIssuer,
	} {
		if !strings.Contains(string(documentation), want) {
			t.Errorf("install documentation does not contain %s %q", name, want)
		}
	}
}
