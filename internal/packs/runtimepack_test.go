package packs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	generated "github.com/tfpreflight/tfpreflight/rules"
)

const testProviderVersion = "6.64.0"

// TestRuntimePackMatchesGeneratedPack checks that the bytes the runtime reads
// through the embed package are the one shipped copy under packs/, so the
// runtime and the pack cannot drift apart.
func TestRuntimePackMatchesGeneratedPack(t *testing.T) {
	t.Parallel()
	repoPack := readPack(t, filepath.Join("..", "..", "packs", "aws", "generated", "aws.json"))
	data, err := packFile("aws/generated/aws-" + testProviderVersion + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var runtimePack generated.Pack
	if err := json.Unmarshal(data, &runtimePack); err != nil {
		t.Fatal(err)
	}
	if len(runtimePack.Resources) != len(repoPack.Resources) {
		t.Fatalf("embedded runtime pack has %d resources but the generated pack has %d; run tools/knowledge-generator to resync", len(runtimePack.Resources), len(repoPack.Resources))
	}
	for resource := range repoPack.Resources {
		if _, ok := runtimePack.Resources[resource]; !ok {
			t.Fatalf("embedded runtime pack is missing %s", resource)
		}
	}
}

func readPack(t *testing.T, path string) generated.Pack {
	t.Helper()
	// The file in packs/ is the range pack; this version's pack is
	// materialized from it.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	ranges, err := generated.ReadRangePack(data)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if data, err = ranges.Materialize(testProviderVersion); err != nil {
		t.Fatal(err)
	}
	var pack generated.Pack
	if err := json.Unmarshal(data, &pack); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return pack
}

// TestRuntimePackResolvesManyResources checks the runtime pack answers for many
// resource types, not a handful.
func TestRuntimePackResolvesManyResources(t *testing.T) {
	t.Parallel()
	pack, loaded, err := LoadRuntimePack(testProviderVersion)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded {
		t.Fatal("generated pack was not layered over the verified pack")
	}
	if len(pack.Resources) < 100 {
		t.Fatalf("runtime pack resolved only %d resources", len(pack.Resources))
	}
	for resource, permission := range map[string]string{
		"aws_vpc":                     "ec2:CreateVpc",
		"aws_subnet":                  "ec2:CreateSubnet",
		"aws_internet_gateway":        "ec2:CreateInternetGateway",
		"aws_placement_group":         "ec2:CreatePlacementGroup",
		"aws_cloudwatch_metric_alarm": "cloudwatch:PutMetricAlarm",
	} {
		rule, ok := pack.Resources[resource]
		if !ok {
			t.Fatalf("runtime pack does not know %s", resource)
		}
		action, ok := rule.Actions["create"]
		if !ok {
			t.Fatalf("%s has no create action", resource)
		}
		if !hasPermission(action, permission) {
			t.Fatalf("%s create does not require %s: %#v", resource, permission, action.Operations)
		}
	}
}

func hasPermission(action ActionRule, permission string) bool {
	for _, operation := range action.Operations {
		if operation.Permission == permission {
			return true
		}
	}
	return false
}

// Knowledge is tied to an exact provider version. A release can change which API
// a resource calls, so a neighbouring version's pack would give confident
// findings about behaviour that no longer exists.
func TestExactProviderVersionIsLoaded(t *testing.T) {
	t.Parallel()
	pack, loaded, err := LoadRuntimePack(testProviderVersion)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded {
		t.Fatalf("pack for %s should be loaded", testProviderVersion)
	}
	if len(pack.Resources) == 0 {
		t.Fatal("loaded pack has no resources")
	}
}

// A version the binary does not ship must not borrow a neighbouring
// version's knowledge, even when packs on either side exist.
func TestUnshippedVersionDoesNotFallBack(t *testing.T) {
	t.Parallel()
	for _, version := range []string{"6.16.0", "6.57.0", "6.70.0", "7.0.0"} {
		pack, loaded, err := LoadRuntimePack(version)
		if err != nil {
			t.Fatalf("%s: %v", version, err)
		}
		if loaded {
			continue // legitimately shipped
		}
		if len(pack.Resources) != 0 {
			t.Fatalf("%s: unsupported version returned %d resources; knowledge must never come from another version", version, len(pack.Resources))
		}
	}
}

// An undetermined provider version is unsupported rather than answered from a
// default pack.
func TestMissingProviderVersionIsUnsupported(t *testing.T) {
	t.Parallel()
	pack, loaded, err := LoadRuntimePack("")
	if err != nil {
		t.Fatal(err)
	}
	if loaded || len(pack.Resources) != 0 {
		t.Fatalf("empty version must be unsupported, got loaded=%v resources=%d", loaded, len(pack.Resources))
	}
}

func TestEverySupportedVersionShipsAnExactPack(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("materializes every shipped version")
	}
	supported, err := SupportedVersions()
	if err != nil {
		t.Fatal(err)
	}
	if len(supported["aws"]) == 0 {
		t.Fatal("no supported AWS versions declared")
	}
	for _, version := range supported["aws"] {
		pack, loaded, err := LoadRuntimePack(version)
		if err != nil {
			t.Fatalf("%s: %v", version, err)
		}
		if !loaded {
			t.Errorf("%s is declared supported but no embedded pack loads for it", version)
			continue
		}
		if len(pack.Resources) == 0 {
			t.Errorf("%s loads an empty pack", version)
		}
	}
}

// A pack must also declare the version it is filed under, so a mislabelled file
// cannot masquerade as support for a version it does not describe.
func TestEmbeddedPacksDeclareTheirOwnVersion(t *testing.T) {
	t.Parallel()
	versions, err := EmbeddedPackVersions()
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range versions {
		data, err := packFile("aws/generated/aws-" + version + ".json")
		if err != nil {
			t.Fatalf("%s: %v", version, err)
		}
		var pack struct {
			Provider        string `json:"provider"`
			ProviderVersion string `json:"provider_version"`
		}
		if err := json.Unmarshal(data, &pack); err != nil {
			t.Fatalf("%s: %v", version, err)
		}
		if pack.Provider != "aws" || pack.ProviderVersion != version {
			t.Errorf("generated/aws-%s.json declares %s %s", version, pack.Provider, pack.ProviderVersion)
		}
	}
}

// Shipping a pack the project never promoted would mean a version became
// supported merely by a file existing, which is what the manifest exists to
// prevent.
func TestEmbeddedPacksAreDeclaredSupported(t *testing.T) {
	t.Parallel()
	supported, err := SupportedVersions()
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	for _, version := range supported["aws"] {
		declared[version] = true
	}
	versions, err := EmbeddedPackVersions()
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range versions {
		if !declared[version] {
			t.Errorf("generated/aws-%s.json ships but is not declared supported; promote it or remove it", version)
		}
	}
}
