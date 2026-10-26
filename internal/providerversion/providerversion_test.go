package providerversion

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func lock(version string) func() (string, error) {
	return func() (string, error) {
		if version == "" {
			return "", errors.New("open .terraform.lock.hcl: no such file or directory")
		}
		return version, nil
	}
}

func config(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ConfigFile)
	if body != "" {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// chooseFrom chooses with the config file at path, as a run does.
func chooseFrom(flag, path string, lockVersion func() (string, error)) (Selection, error) {
	config, err := ReadConfig(path)
	if err != nil {
		return Selection{}, err
	}
	lock, lockErr := lockVersion()
	return Choose(flag, config.ProviderVersion, lock, lockErr)
}

// The flag wins over the config file, which wins over the lock file.
func TestPrecedenceFlagConfigLock(t *testing.T) {
	withConfig := config(t, "# project\nprovider_version: \"6.60.0\"\n")
	for _, c := range []struct {
		name, flag, config, lock, want string
		source                         Source
	}{
		{"flag over all", "6.50.0", withConfig, "6.64.0", "6.50.0", SourceFlag},
		{"config over lock", "", withConfig, "6.64.0", "6.60.0", SourceConfig},
		{"lock alone", "", config(t, ""), "6.64.0", "6.64.0", SourceLock},
		{"flag without lock", "6.64.0", config(t, ""), "", "6.64.0", SourceFlag},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := chooseFrom(c.flag, c.config, lock(c.lock))
			if err != nil {
				t.Fatal(err)
			}
			if got.Version != c.want || got.Source != c.source || got.LockVersion != c.lock {
				t.Fatalf("got %+v, want %s from %s, lock %q", got, c.want, c.source, c.lock)
			}
		})
	}
}

func TestNoVersionIsAToolFailureThatSaysWhatToDo(t *testing.T) {
	_, err := chooseFrom("", config(t, ""), lock(""))
	if err == nil || !strings.Contains(err.Error(), "--provider-version") || !strings.Contains(err.Error(), ConfigFile) {
		t.Fatalf("err = %v", err)
	}
}

func TestConfigAndFlagMustBeExactAndKnown(t *testing.T) {
	for _, c := range []struct{ flag, body, want string }{
		{"~> 6.0", "", "not an exact version"},
		{"", "provider_version: latest\n", "not an exact version"},
		{"", "provider-version: 6.64.0\n", "unknown setting"},
		{"", "provider_version:\n", "single value"},
	} {
		if _, err := chooseFrom(c.flag, config(t, c.body), lock("6.64.0")); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("flag %q config %q: err = %v, want %q", c.flag, c.body, err, c.want)
		}
	}
	got, err := chooseFrom("", config(t, "provider_version: '6.61.0'  # pinned\n"), lock("6.64.0"))
	if err != nil || got.Version != "6.61.0" {
		t.Fatalf("single-quoted value: %+v, %v", got, err)
	}
}

func TestModes(t *testing.T) {
	covered := []string{"6.67.0", "6.9.0", "6.40.0", "6.64.0"}
	for _, c := range []struct {
		version string
		mode    Mode
		rules   string
	}{
		{"6.64.0", ModeCovered, "6.64.0"},
		{"6.9.0", ModeCovered, "6.9.0"},
		{"6.70.0", ModeNewer, "6.67.0"},
		{"5.100.0", ModeOlder, "6.9.0"},
		{"6.10.0", ModeGap, "6.9.0"},
		{"6.65.0", ModeGap, "6.64.0"},
	} {
		got, err := Selection{Version: c.version, Source: SourceLock}.Resolve(covered)
		if err != nil {
			t.Fatal(err)
		}
		if got.Mode != c.mode || got.RulesVersion != c.rules {
			t.Errorf("%s: %s with %s rules, want %s with %s", c.version, got.Mode, got.RulesVersion, c.mode, c.rules)
		}
		if got.Blocking() != (c.mode == ModeCovered) {
			t.Errorf("%s: blocking %v in mode %s", c.version, got.Blocking(), got.Mode)
		}
		if !strings.Contains(got.Summary(), string(c.mode)) {
			t.Errorf("summary %q does not name %s", got.Summary(), c.mode)
		}
	}
	if _, err := (Selection{Version: "6.64.0"}).Resolve(nil); err == nil {
		t.Fatal("no covered versions resolved")
	}
}

func TestMismatchIsAgainstTheLockFile(t *testing.T) {
	if (Selection{Version: "6.64.0", LockVersion: "6.64.0"}).Mismatch() || (Selection{Version: "6.64.0"}).Mismatch() {
		t.Fatal("no mismatch reported as one")
	}
	if !(Selection{Version: "6.60.0", LockVersion: "6.64.0"}).Mismatch() {
		t.Fatal("mismatch missed")
	}
}
