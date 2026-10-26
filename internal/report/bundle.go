package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/tfpreflight/tfpreflight/rules/model"
)

// BundleSchemaVersion versions the support bundle apart from the JSON report.
// Bundles are JSON so a user can inspect every byte before sharing.
const BundleSchemaVersion = "1"

// Bundle is a support file for reporting a wrong result.
type Bundle struct {
	BundleSchemaVersion string          `json:"bundle_schema_version"`
	Tfpreflight         BundleBuild     `json:"tfpreflight"`
	PackID              string          `json:"pack_id"`
	Provider            BundleProvider  `json:"provider"`
	Redaction           BundleRedaction `json:"redaction"`
	Report              Document        `json:"report"`
}

// BundleBuild identifies the tfpreflight build that produced a bundle.
type BundleBuild struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// BundleProvider is the provider version, how it relates to the covered
// versions, and whose rules ran.
type BundleProvider struct {
	Version      string `json:"version,omitempty"`
	Mode         string `json:"mode,omitempty"`
	RulesVersion string `json:"rules_version,omitempty"`
}

// BundleRedaction says whether sensitive values were kept and which fields were
// removed.
type BundleRedaction struct {
	SensitiveValuesIncluded bool     `json:"sensitive_values_included"`
	Excluded                []string `json:"excluded"`
}

// NewBundle creates a bundle. By default it removes every free-form string and
// the AWS context, which can hold plan values, identities, ARNs, account IDs,
// paths and resource names. Resource addresses become stable aliases, so
// findings still match coverage.
func NewBundle(document Document, version, commit, packID string, includeSensitive bool) Bundle {
	bundle := Bundle{
		BundleSchemaVersion: BundleSchemaVersion,
		Tfpreflight:         BundleBuild{Version: version, Commit: commit},
		PackID:              packID,
		Provider: BundleProvider{
			Version: document.Provider.Version, Mode: document.Provider.Mode,
			RulesVersion: document.Provider.RulesVersion,
		},
		Redaction: BundleRedaction{SensitiveValuesIncluded: includeSensitive, Excluded: []string{}},
		Report:    document,
	}
	if !includeSensitive {
		bundle.Redaction.Excluded = []string{"account IDs", "ARNs", "plan values", "resource names"}
		bundle.Report = redactDocument(document)
	}
	return bundle
}

// MarshalBundle returns the exact bytes written to disk and previewed.
func MarshalBundle(bundle Bundle) ([]byte, error) {
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func redactDocument(document Document) Document {
	redacted := document
	redacted.AWSContext = nil
	redacted.Error = ""

	resources := map[string]bool{}
	for _, finding := range document.Findings {
		if finding.Resource != "" {
			resources[finding.Resource] = true
		}
	}
	for _, coverage := range document.Coverage {
		if coverage.Resource != "" {
			resources[coverage.Resource] = true
		}
	}
	names := make([]string, 0, len(resources))
	for resource := range resources {
		names = append(names, resource)
	}
	sort.Strings(names)
	aliases := make(map[string]string, len(names))
	for i, resource := range names {
		aliases[resource] = resourceAlias(i + 1)
	}

	redacted.Findings = make([]Finding, len(document.Findings))
	for i, finding := range document.Findings {
		finding.Resource = aliases[finding.Resource]
		finding.Message = "[redacted]"
		finding.Reason = ""
		redacted.Findings[i] = finding
	}
	redacted.Coverage = make([]ResourceCoverage, len(document.Coverage))
	for i, coverage := range document.Coverage {
		coverage.Resource = aliases[coverage.Resource]
		coverage.Reasons = []string{}
		coverage.Checks = copyChecks(coverage.Checks)
		redacted.Coverage[i] = coverage
	}
	return redacted
}

func resourceAlias(n int) string {
	return fmt.Sprintf("resource-%03d", n)
}

func copyChecks(source map[string]model.CheckStatus) map[string]model.CheckStatus {
	copied := make(map[string]model.CheckStatus, len(source))
	for name, status := range source {
		copied[name] = status
	}
	return copied
}

// WriteBundle writes the bundle to path, readable by its owner only, and
// previews its exact contents so they are reviewed before sharing.
func WriteBundle(preview io.Writer, path string, bundle Bundle) error {
	data, err := MarshalBundle(bundle)
	if err != nil {
		return fmt.Errorf("encode support bundle: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create support bundle %s: %w", path, err)
	}
	writeErr := func() error {
		if err := file.Chmod(0o600); err != nil {
			return err
		}
		if _, err := file.Write(data); err != nil {
			return err
		}
		return file.Sync()
	}()
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("write support bundle %s: %w", path, writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close support bundle %s: %w", path, closeErr)
	}
	if _, err := fmt.Fprintf(preview, "\nSupport bundle exact contents (%s):\n%sReview this file before sharing it.\n", path, data); err != nil {
		return fmt.Errorf("preview support bundle: %w", err)
	}
	return nil
}
