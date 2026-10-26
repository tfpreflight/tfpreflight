// Package providerversion decides which AWS provider version a check describes,
// and which covered version's rules it uses.
//
// The version comes from the --provider-version flag, else provider_version in
// .tfpreflight.yml, else .terraform.lock.hcl. A version the packs do not cover
// is still checked, with the nearest covered rules, but as warnings only: those
// rules were never built for it.
package providerversion

import (
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/tfpreflight/tfpreflight/rules"
	"go.yaml.in/yaml/v3"
)

// ConfigFile is the project configuration file, in the working directory.
const ConfigFile = ".tfpreflight.yml"

// LockFile is Terraform's dependency lock file.
const LockFile = ".terraform.lock.hcl"

// Source is where the version came from.
type Source string

// Where a version can come from.
const (
	SourceFlag   Source = "flag"
	SourceConfig Source = "config"
	SourceLock   Source = "lock"
)

// Mode is how the version relates to the versions the packs cover. Only
// ModeCovered lets a finding block.
type Mode string

const (
	// ModeCovered means the packs cover this exact version.
	ModeCovered Mode = "COVERED"
	// ModeNewer is newer than every covered version; the newest rules, warnings
	// only.
	ModeNewer Mode = "NEWER"
	// ModeOlder is older than every covered version; the oldest rules, warnings
	// only.
	ModeOlder Mode = "OLDER"
	// ModeGap is inside the covered range but not built; the nearest older
	// version's rules, warnings only.
	ModeGap Mode = "GAP"
)

// Selection is the version a check describes and the rules it uses.
type Selection struct {
	// Version is the version the check describes, and Source where it came from.
	Version string
	Source  Source
	// LockVersion is what .terraform.lock.hcl selects, when it can be read.
	LockVersion string
	// Mode relates Version to Covered; RulesVersion is the covered version whose
	// rules run.
	Mode         Mode
	RulesVersion string
	Covered      []string
}

// Blocking reports whether findings may block: only on a covered version.
func (s Selection) Blocking() bool { return s.Mode == ModeCovered }

// Mismatch reports whether the check describes a version other than the lock
// file's.
func (s Selection) Mismatch() bool {
	return s.LockVersion != "" && s.Version != s.LockVersion
}

var exact = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// Choose picks the version: the flag's, else configured, the config file's, else
// the lock file's. The lock file's error is reported only when nothing else
// names a version.
func Choose(flagVersion, configured, lock string, lockErr error) (Selection, error) {
	selection := Selection{LockVersion: lock}
	if lockErr != nil {
		selection.LockVersion = ""
	}
	switch {
	case flagVersion != "":
		selection.Version, selection.Source = flagVersion, SourceFlag
	case configured != "":
		selection.Version, selection.Source = configured, SourceConfig
	case lockErr == nil:
		selection.Version, selection.Source = lock, SourceLock
	default:
		return Selection{}, fmt.Errorf("no AWS provider version: pass --provider-version, set provider_version in %s, or run terraform init so %s names the AWS provider (%v)", ConfigFile, LockFile, lockErr) //nolint:errorlint // The message is user-visible and the lock error is only context; wrapping it would let errors.Is match lockErr.
	}
	if !exact.MatchString(selection.Version) {
		return Selection{}, fmt.Errorf("AWS provider version %q (from %s) is not an exact version such as 6.64.0", selection.Version, DescribeSource(selection.Source))
	}
	return selection, nil
}

// DescribeSource names where a version came from, for people.
func DescribeSource(source Source) string {
	switch source {
	case SourceFlag:
		return "--provider-version"
	case SourceConfig:
		return ConfigFile
	default:
		return LockFile
	}
}

// Config is the settings .tfpreflight.yml can hold.
type Config struct {
	ProviderVersion string
	// FailOn is "error" or "warning"; "" when not set.
	FailOn string
	// FailOnPartial is nil when not set.
	FailOnPartial *bool
}

// ReadConfig reads the configuration file, a YAML mapping of settings. A missing
// or empty file has no settings. Anything but a known setting with a valid value
// is an error, so a typo never falls back to a default.
func ReadConfig(path string) (Config, error) {
	var config Config
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return config, nil
	}
	if err != nil {
		return config, fmt.Errorf("read %s: %w", path, err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return config, fmt.Errorf("%s: %w", path, err)
	}
	if len(document.Content) == 0 {
		return config, nil
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return config, fmt.Errorf("%s line %d: expected settings as key: value", path, root.Line)
	}
	seen := map[string]int{}
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		if first, found := seen[key.Value]; found {
			return config, fmt.Errorf("%s line %d: %s is already set on line %d", path, key.Line, key.Value, first)
		}
		seen[key.Value] = key.Line
		if err := config.set(key.Value, value); err != nil {
			return config, fmt.Errorf("%s line %d: %w", path, key.Line, err)
		}
	}
	return config, nil
}

func (c *Config) set(key string, value *yaml.Node) error {
	if key != "provider_version" && key != "fail_on" && key != "fail_on_partial" {
		return fmt.Errorf("unknown setting %q (the settings are provider_version, fail_on and fail_on_partial)", key)
	}
	if value.Kind != yaml.ScalarNode || value.Tag == "!!null" || value.Value == "" {
		return fmt.Errorf("%s must be a single value", key)
	}
	switch key {
	case "provider_version":
		c.ProviderVersion = value.Value
	case "fail_on":
		if value.Value != "error" && value.Value != "warning" {
			return fmt.Errorf("fail_on must be error or warning, not %q", value.Value)
		}
		c.FailOn = value.Value
	default:
		// YAML 1.2 booleans only: "yes" is a string, not true.
		var enabled bool
		if value.Tag != "!!bool" || value.Decode(&enabled) != nil {
			return fmt.Errorf("fail_on_partial must be true or false, not %q", value.Value)
		}
		c.FailOnPartial = &enabled
	}
	return nil
}

// Resolve places the version among the covered versions and picks the rules for
// it.
func (s Selection) Resolve(covered []string) (Selection, error) {
	if len(covered) == 0 {
		return Selection{}, errors.New("the rules cover no AWS provider version")
	}
	versions := append([]string(nil), covered...)
	rules.SortVersions(versions)
	s.Covered = versions
	oldest, newest := versions[0], versions[len(versions)-1]
	switch {
	case rules.CompareVersions(s.Version, newest) > 0:
		s.Mode, s.RulesVersion = ModeNewer, newest
	case rules.CompareVersions(s.Version, oldest) < 0:
		s.Mode, s.RulesVersion = ModeOlder, oldest
	default:
		s.Mode = ModeGap
		for _, v := range versions {
			if v == s.Version {
				s.Mode, s.RulesVersion = ModeCovered, v
				break
			}
			if rules.CompareVersions(v, s.Version) < 0 {
				s.RulesVersion = v
			}
		}
	}
	return s, nil
}

// Summary is the line the output leads with.
func (s Selection) Summary() string {
	head := fmt.Sprintf("AWS provider %s (from %s): %s", s.Version, DescribeSource(s.Source), s.Mode)
	switch s.Mode {
	case ModeCovered:
		return head + "; this tfpreflight has rules for this exact version"
	case ModeNewer:
		return head + fmt.Sprintf(" than every version this tfpreflight covers (newest %s). Using %s rules; every finding is a warning and nothing blocks. Run tfpreflight update for rules built for %s.", s.RulesVersion, s.RulesVersion, s.Version)
	case ModeOlder:
		return head + fmt.Sprintf(" than every version this tfpreflight covers (oldest %s). Using %s rules; every finding is a warning and nothing blocks.", s.RulesVersion, s.RulesVersion)
	default:
		return head + fmt.Sprintf(", between versions this tfpreflight covers, but never built. Using %s rules, the nearest older covered version; every finding is a warning and nothing blocks.", s.RulesVersion)
	}
}
