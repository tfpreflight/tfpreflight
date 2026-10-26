package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/packs"
)

// The CLI tests never read a real user's downloaded packs.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "tfpreflight-cli-packs-")
	if err != nil {
		panic(err)
	}
	if err := os.Setenv(packs.CacheEnv, dir); err != nil {
		panic(err)
	}
	if err := os.Unsetenv(packs.IndexEnv); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// A check with --update and no network keeps the rules in use, says so, and
// completes as it would have.
func TestCheckUpdateOfflineIsNeverACheckFailure(t *testing.T) {
	dir := cliProject(t, "clean")
	code, out, diagnostics := cliProcess(t, dir, "clean", "check", "--plan=tfplan", "--format=json", "--update", "--index=http://127.0.0.1:1/index.json")
	if code != 0 || !strings.Contains(diagnostics, "tfpreflight: warning: could not fetch the rules") || !strings.Contains(diagnostics, "keeping the rules in use") || !strings.Contains(out, `"exit_classification": "completed"`) {
		t.Fatalf("code %d\nstdout %s\nstderr %s", code, out, diagnostics)
	}
}

// tfpreflight update exits 2 whenever the newest packs are not in the cache
// afterwards, however the index could not be fetched.
func TestUpdateThatCannotFetchTheIndexFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/missing/index.json") {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	dir := cliProject(t, "clean")
	for name, index := range map[string]string{
		"unreachable":        "http://127.0.0.1:1/index.json",
		"HTTP 404":           server.URL + "/missing/index.json",
		"HTTP 503":           server.URL + "/index.json",
		"missing local file": filepath.Join(dir, "no-such-index.json"),
	} {
		t.Run(name, func(t *testing.T) {
			code, out, diagnostics := cliProcess(t, dir, "clean", "update", "--index="+index)
			if code != 2 || !strings.Contains(diagnostics, "tfpreflight: rules not updated; the rules in use are unchanged: could not fetch the rules") {
				t.Fatalf("code %d\nstdout %s\nstderr %s", code, out, diagnostics)
			}
		})
	}
}

func TestUpdateWithoutAnIndexSaysWhatToSet(t *testing.T) {
	dir := cliProject(t, "clean")
	code, out, diagnostics := cliProcess(t, dir, "clean", "update")
	if code != 2 || !strings.Contains(out+diagnostics, packs.IndexEnv) {
		t.Fatalf("code %d\nstdout %s\nstderr %s", code, out, diagnostics)
	}
}

func TestVersionNamesThePacksInUse(t *testing.T) {
	dir := cliProject(t, "clean")
	code, out, _ := cliProcess(t, dir, "clean", "version")
	for _, want := range []string{"Rules: built in\n", "AWS provider rules: ", "no rules between 5.100.0 and 6.17.0\n"} {
		if code != 0 || !strings.Contains(out, want) {
			t.Fatalf("version output lacks %q:\n%s", want, out)
		}
	}
}
