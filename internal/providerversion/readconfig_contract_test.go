package providerversion

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every way ReadConfig can end, with the exact error text and parsed values.
// {path} stands for the config file's path.
func TestReadConfigContract(t *testing.T) {
	enabled, disabled := true, false
	for _, test := range []struct {
		name string
		body string
		want Config
		err  string
	}{
		{name: "comments, document marker and quoting", body: "---\n# project\nprovider_version: \"6.60.0\" # pinned\nfail_on: 'warning'\nfail_on_partial: true\n", want: Config{ProviderVersion: "6.60.0", FailOn: "warning", FailOnPartial: &enabled}},
		{name: "unquoted values", body: "fail_on: error\nfail_on_partial: false\n", want: Config{FailOn: "error", FailOnPartial: &disabled}},
		{name: "hash inside quotes", body: "provider_version: \"6.60.0#x\"\n", want: Config{ProviderVersion: "6.60.0#x"}},
		{name: "empty file", body: "# nothing set\n", want: Config{}},
		{name: "not a mapping", body: "provider_version 6.60.0\n", err: "{path} line 1: expected settings as key: value"},
		{name: "empty value", body: "\nprovider_version: \"\"\n", err: "{path} line 2: provider_version must be a single value"},
		{name: "null value", body: "fail_on:\n", err: "{path} line 1: fail_on must be a single value"},
		{name: "nested value", body: "fail_on:\n  level: error\n", err: "{path} line 1: fail_on must be a single value"},
		{name: "bad fail_on", body: "fail_on: info\n", err: `{path} line 1: fail_on must be error or warning, not "info"`},
		{name: "bad fail_on_partial", body: "fail_on_partial: maybe\n", err: `{path} line 1: fail_on_partial must be true or false, not "maybe"`},
		{name: "YAML 1.1 yes", body: "fail_on_partial: yes\n", err: `{path} line 1: fail_on_partial must be true or false, not "yes"`},
		{name: "quoted true", body: "fail_on_partial: \"true\"\n", err: `{path} line 1: fail_on_partial must be true or false, not "true"`},
		{name: "unknown setting", body: "fail_on: error\nstrict: true\n", err: `{path} line 2: unknown setting "strict" (the settings are provider_version, fail_on and fail_on_partial)`},
		{name: "duplicate setting", body: "fail_on: error\nfail_on: warning\n", err: "{path} line 2: fail_on is already set on line 1"},
		{name: "not YAML", body: "fail_on: [error\n", err: "{path}: yaml: line 1: did not find expected ',' or ']'"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := config(t, test.body)
			got, err := ReadConfig(path)
			assertConfigError(t, err, strings.ReplaceAll(test.err, "{path}", path))
			if test.err == "" && describeConfig(got) != describeConfig(test.want) {
				t.Errorf("config = %s, want %s", describeConfig(got), describeConfig(test.want))
			}
		})
	}
}

// A missing file is no configuration; an unreadable one is an error.
func TestReadConfigFileStates(t *testing.T) {
	missing := filepath.Join(t.TempDir(), ConfigFile)
	if got, err := ReadConfig(missing); err != nil || describeConfig(got) != describeConfig(Config{}) {
		t.Errorf("missing file = %s, %v; want empty config, no error", describeConfig(got), err)
	}
	directory := filepath.Join(t.TempDir(), ConfigFile)
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := ReadConfig(directory)
	assertConfigError(t, err, "read "+directory+": read "+directory+": is a directory")
}

func assertConfigError(t *testing.T, err error, want string) {
	t.Helper()
	got := ""
	if err != nil {
		got = err.Error()
	}
	if got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
}

func describeConfig(c Config) string {
	partial := "unset"
	if c.FailOnPartial != nil {
		partial = fmt.Sprint(*c.FailOnPartial)
	}
	return fmt.Sprintf("{provider_version:%q fail_on:%q fail_on_partial:%s}", c.ProviderVersion, c.FailOn, partial)
}
