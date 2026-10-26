package packs_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/internal/checks/conflicts"
	"github.com/tfpreflight/tfpreflight/packs"
	"github.com/tfpreflight/tfpreflight/rules"
)

const repoRoot = ".."

// read reads a file of the repository. A per-version pack, such as
// packs/aws/dependency/rules-6.64.0.json, is materialized from its range
// pack.
func read(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, path))
	if err == nil {
		return data
	}
	if data, ok := materializedVersion(t, path); ok {
		return data
	}
	t.Fatalf("read %s: %v", path, err)
	return nil
}

// materializedVersion reads a per-version pack path out of its range pack.
// ok is false when the path names no version or no range pack holds it.
func materializedVersion(t *testing.T, path string) ([]byte, bool) {
	t.Helper()
	m := perVersion.FindStringSubmatch(filepath.ToSlash(path))
	if m == nil {
		return nil, false
	}
	name := strings.TrimPrefix(perVersion.ReplaceAllString(filepath.ToSlash(path), "-"+rules.VersionToken+".json"), "packs/")
	packData, err := os.ReadFile(filepath.Join(repoRoot, "packs", rules.RangePackPath(name)))
	if err != nil {
		return nil, false
	}
	pack, err := rules.ReadRangePack(packData)
	if err != nil {
		t.Fatal(err)
	}
	data, err := pack.Materialize(m[1])
	if err != nil {
		t.Fatal(err)
	}
	return data, true
}

var perVersion = regexp.MustCompile(`-(\d+\.\d+\.\d+)\.json$`)

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Two copies of a pack can drift, and then the binary ships analysis nobody
// reviewed. This fails if a second copy of any shipped pack appears anywhere
// in the repository, or if what go:embed exposes stops matching packs/ on disk.
func TestEveryShippedPackHasOneCopy(t *testing.T) {
	shipped := embeddedPackDigests(t)
	if len(shipped) == 0 {
		t.Fatal("no shipped packs found")
	}
	assertNoSecondCopies(t, shipped)
}

// embeddedPackDigests maps each embedded pack's digest to its path, after
// checking it matches the file on disk.
func embeddedPackDigests(t *testing.T) map[string]string {
	t.Helper()
	shipped := map[string]string{}
	err := fs.WalkDir(packs.AWS, "aws", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		embedded, err := packs.AWS.ReadFile(path)
		if err != nil {
			return err
		}
		if digest(embedded) != digest(read(t, filepath.Join("packs", path))) {
			t.Errorf("packs/%s on disk differs from the embedded copy", path)
		}
		shipped[digest(embedded)] = "packs/" + path
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return shipped
}

// assertNoSecondCopies fails for any JSON file outside packs/ whose bytes are
// a shipped pack's.
func assertNoSecondCopies(t *testing.T, shipped map[string]string) {
	t.Helper()
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if entry.IsDir() {
			// .build is the git-ignored build cache, where the provider
			// pipeline stages candidates: a freshly promoted candidate equals
			// its pack. It is never committed.
			if rel == ".git" || rel == "packs" || rel == ".build" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".json" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if original, found := shipped[digest(data)]; found {
			t.Errorf("%s is a second copy of %s; a shipped pack lives only in packs/", rel, original)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A generated conflict rule stays a warning. A projection must never be able to
// turn one into a blocking finding.
func TestConflictProjectionNeverPromotesTrust(t *testing.T) {
	var embedded rules.RuntimeRuleFile
	if err := json.Unmarshal(read(t, "packs/aws/conflict/generated-aws-6.64.0.json"), &embedded); err != nil {
		t.Fatal(err)
	}
	for _, rule := range embedded.Rules {
		if rule.Trust != "generated" {
			t.Errorf("%s has trust %q in the generated pack; only the curated pack may be verified", rule.ResourceType, rule.Trust)
		}
	}
}

// A conflict family the resolver has no behaviour for must stop generation
// rather than be mapped to something plausible.
func TestConflictProjectionRefusesUnknownSemantics(t *testing.T) {
	for _, family := range []string{"quota", "state_precondition", "dependency", "other", "unknown", ""} {
		if _, err := rules.RuntimeSemantics(family); err == nil {
			t.Errorf("family %q was mapped to runtime semantics instead of refusing", family)
		}
	}
	if got, err := rules.RuntimeSemantics("duplicate_conflict"); err != nil || got != conflicts.SemanticsDuplicateError {
		t.Fatalf("duplicate_conflict = %q %v", got, err)
	}
}

// The runtime decodes quota rules into rules.Rule. Every field in the pack must
// decode into it, so a field the runtime would silently drop fails here.
func TestQuotaRuntimePackMatchesKnowledge(t *testing.T) {
	var embedded struct {
		ProviderVersion string       `json:"provider_version"`
		Rules           []rules.Rule `json:"rules"`
	}
	decoder := json.NewDecoder(bytes.NewReader(read(t, "packs/aws/generated/quota-aws-6.64.0.json")))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&embedded); err != nil {
		t.Fatalf("quota pack does not decode into quotas.Rule exactly: %v", err)
	}
	if embedded.ProviderVersion != "6.64.0" {
		t.Fatalf("quota pack version = %q, want 6.64.0", embedded.ProviderVersion)
	}
	if len(embedded.Rules) == 0 {
		t.Fatal("quota pack has no rules")
	}
	// Reproducibility is the point of this test, not a coverage change: a
	// generated quota rule must not become verified by being carried into the
	// runtime pack.
	for _, rule := range embedded.Rules {
		if rule.BlockingSafe() {
			t.Errorf("quota rule %s is blocking-safe in the runtime pack; this remediation must not promote trust", rule.Resource)
		}
	}
}

// The manifest lists every version the set covers, and every range pack
// covers exactly those.
func TestManifestVersionsMatchEveryRangePack(t *testing.T) {
	var manifest rules.Manifest
	if err := json.Unmarshal(read(t, "packs/aws/manifest.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Versions) == 0 {
		t.Fatal("the manifest lists no versions")
	}
	ranges := 0
	for name := range manifest.Files {
		data := read(t, filepath.Join("packs", name))
		if !rules.IsRangePack(data) {
			continue
		}
		ranges++
		pack, err := rules.ReadRangePack(data)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(pack.Versions, " ") != strings.Join(manifest.Versions, " ") {
			t.Errorf("%s covers %v, the manifest %v", name, pack.Versions, manifest.Versions)
		}
	}
	if ranges < 10 {
		t.Fatalf("%d range packs", ranges)
	}
}

// machinePath reports whether a value names a place on the machine that built
// the pack: an absolute path, a home directory, or a ~ path.
// filesystemRoot matches an absolute path under a real filesystem root. Packs
// legitimately hold HTTP request paths such as /2015-03-31/functions/{Name},
// which name no machine.
var filesystemRoot = regexp.MustCompile(`^/(Users|home|root|var|tmp|private|opt|etc|usr|Library|System|Volumes|mnt|srv|nix|snap)(/|$)`)

func machinePath(value, home string) bool {
	switch {
	case filesystemRoot.MatchString(value), strings.HasPrefix(value, "~"), strings.HasPrefix(value, `\\`):
		return true
	case len(value) > 2 && value[1] == ':' && (value[2] == '\\' || value[2] == '/'):
		return true
	case strings.Contains(value, "/Users/"), strings.Contains(value, "/home/"):
		return true
	case home != "" && home != "/" && strings.Contains(value, home):
		return true
	}
	return false
}

// A shipped pack must be the same bytes whoever builds it. A source path that
// names the builder's home directory or cache is not, and it publishes their
// username in every binary.
func TestShippedPacksContainNoMachinePaths(t *testing.T) {
	home, _ := os.UserHomeDir()
	err := fs.WalkDir(packs.AWS, "aws", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := packs.AWS.ReadFile(path)
		if err != nil {
			return err
		}
		var document any
		if err := json.Unmarshal(data, &document); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		found := machinePaths(document, "", home)
		for _, hit := range found[:min(len(found), 3)] {
			t.Errorf("packs/%s%s = %q names the machine that built it", path, hit.at, hit.value)
		}
		if len(found) > 3 {
			t.Errorf("packs/%s: %d machine paths in all", path, len(found))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

type machinePathHit struct{ at, value string }

// machinePaths finds every string in a pack document that names a path on
// the machine that built it, with where it sits.
func machinePaths(value any, at, home string) []machinePathHit {
	switch value := value.(type) {
	case map[string]any:
		var hits []machinePathHit
		for key, child := range value {
			hits = append(hits, machinePaths(child, at+"."+key, home)...)
		}
		return hits
	case []any:
		var hits []machinePathHit
		for index, child := range value {
			hits = append(hits, machinePaths(child, fmt.Sprintf("%s[%d]", at, index), home)...)
		}
		return hits
	case string:
		if machinePath(value, home) {
			return []machinePathHit{{at, value}}
		}
	}
	return nil
}

func TestMachinePathRecognisesBuilderPaths(t *testing.T) {
	for value, want := range map[string]bool{
		"/Users/someone/Library/Caches/terraform-provider-aws/6.64.0/internal/service/s3/bucket.go": true,
		"/home/ci/.cache/x.go":  true,
		`C:\Users\someone\x.go`: true,
		"~/x.go":                true,
		"internal/service/elbv2/load_balancer.go": false,
		"/var/folders/b2/x/T/tfpreflight":         true,
		"/tmp/x.go":                               true,
		"/workspaces/{workspaceId}":               false,
		"/2015-03-31/functions/{FunctionName}":    false,
		"/":                                       false,
		"s3:CreateBucket":                         false,
		"arn:aws:iam::aws:policy/ReadOnlyAccess":  false,
	} {
		if got := machinePath(value, ""); got != want {
			t.Errorf("machinePath(%q) = %v, want %v", value, got, want)
		}
	}
}

// Every rule that rests on a verification record carries a summary of it: what
// was observed, when, the record's path and SHA-256, or why there is no record.
// These checks need only the packs.
func TestEvidenceBackedRulesCarrySummaries(t *testing.T) {
	sha := regexp.MustCompile(`^[0-9a-f]{64}$`)
	wellFormed := func(where string, s *rules.EvidenceSummary) {
		t.Helper()
		switch {
		case s == nil:
			t.Errorf("%s has no evidence summary", where)
		case s.Observed == "" || s.ObservedAt == "" || s.ObservedAtSource == "":
			t.Errorf("%s: the summary does not say what was observed and when: %+v", where, *s)
		case s.Record == "" && s.NoRecord == "":
			t.Errorf("%s: the summary names no record and does not say why", where)
		case s.Record != "" && (!strings.HasPrefix(s.Record, "records/") || !sha.MatchString(s.SHA256)):
			t.Errorf("%s: the summary's record %q or SHA-256 %q is malformed", where, s.Record, s.SHA256)
		}
	}

	var verified struct {
		Resources map[string]json.RawMessage        `json:"resources"`
		Evidence  map[string]*rules.EvidenceSummary `json:"evidence"`
	}
	if err := json.Unmarshal(read(t, "packs/aws/generated/verified-aws-6.64.0.json"), &verified); err != nil {
		t.Fatal(err)
	}
	for resource := range verified.Resources {
		wellFormed("verified permissions for "+resource, verified.Evidence[resource])
		if s := verified.Evidence[resource]; s != nil && s.Record == "" {
			t.Errorf("verified permissions for %s rest on no record", resource)
		}
	}

	var curated struct {
		Rules []struct {
			ResourceType string                 `json:"resource_type"`
			Evidence     *rules.EvidenceSummary `json:"evidence"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(read(t, "packs/aws/conflict/aws-6.64.0.json"), &curated); err != nil {
		t.Fatal(err)
	}
	for _, rule := range curated.Rules {
		wellFormed("curated conflict rule for "+rule.ResourceType, rule.Evidence)
	}

	var enforcement struct {
		Claims []struct {
			Fingerprint struct{ Resource, Attribute string } `json:"fingerprint"`
			Observation string                               `json:"observation"`
			Evidence    *rules.EvidenceSummary               `json:"evidence"`
		} `json:"claims"`
	}
	if err := json.Unmarshal(read(t, "packs/aws/dependency/enforcement-6.64.0.json"), &enforcement); err != nil {
		t.Fatal(err)
	}
	for _, claim := range enforcement.Claims {
		where := "enforcement claim " + claim.Fingerprint.Resource + "." + claim.Fingerprint.Attribute
		wellFormed(where, claim.Evidence)
		if claim.Evidence != nil && !strings.HasSuffix(claim.Evidence.Record, "/"+claim.Observation) {
			t.Errorf("%s: the summary names %s, the claim names %s", where, claim.Evidence.Record, claim.Observation)
		}
	}
	if len(verified.Resources) == 0 || len(curated.Rules) == 0 || len(enforcement.Claims) == 0 {
		t.Fatal("an evidence-backed pack is empty")
	}
}
