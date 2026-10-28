package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/check"
)

func TestInvokedName(t *testing.T) {
	for arg0, want := range map[string]string{
		"tfp":                          "tfp",
		"/opt/homebrew/bin/tfp":        "tfp",
		"tfp.exe":                      "tfp",
		"tfpreflight":                  "tfpreflight",
		"/usr/local/bin/tfpreflight":   "tfpreflight",
		"/tmp/go-build123/exe/tfptest": "tfpreflight",
	} {
		if got := invokedName(arg0); got != want {
			t.Errorf("invokedName(%q) = %q, want %q", arg0, got, want)
		}
	}
}

// Run as tfp, the usage lines and examples say tfp; the program's own name
// stays in its description and messages.
func TestHelpUsesTheInvokedName(t *testing.T) {
	for _, tc := range []struct {
		name, want, notWant string
	}{
		{"tfp", "  tfp check --plan=tfplan", "  tfpreflight check --plan=tfplan"},
		{"tfpreflight", "  tfpreflight check --plan=tfplan", "  tfp check"},
	} {
		root := rootWithServices(check.Production())
		useName(root, tc.name)
		var out, diagnostics bytes.Buffer
		if code := runRoot(context.Background(), root, []string{"check", "--help"}, &out, &diagnostics); code != 0 {
			t.Fatalf("%s check --help exited %d: %s", tc.name, code, diagnostics.String())
		}
		help := out.String()
		if !strings.Contains(help, "Usage:\n  "+tc.name+" check [flags]") || !strings.Contains(help, tc.want) || strings.Contains(help, tc.notWant) {
			t.Errorf("%s check --help:\n%s", tc.name, help)
		}
		if !strings.Contains(help, "apply failures tfpreflight can predict") {
			t.Errorf("%s check --help lost the program's name in its description:\n%s", tc.name, help)
		}
	}
}
