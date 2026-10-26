package packs

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tfpreflight/tfpreflight/rules"
)

const contractBundle = "2026-10-13.1"

func publishContractBundle(b *testBundles) { b.publish(contractBundle, time.Now(), nil) }

func installContractBundle(b *testBundles) {
	publishContractBundle(b)
	if _, err := b.update(); err != nil {
		b.t.Fatal(err)
	}
}

func signIndexWithOtherKey(b *testBundles) {
	publishContractBundle(b)
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.t.Fatal(err)
	}
	b.sign(other)
}

func corruptContractArchive(b *testBundles) {
	publishContractBundle(b)
	name := "tfpreflight-packs-" + contractBundle + ".tar.gz"
	b.files[name] = flipLastByte(b.files[name])
}

func requireNewerSchema(b *testBundles) {
	publishContractBundle(b)
	b.index.Bundles[0].PackSchemaVersion = rules.SchemaVersion + 1
	b.sign(b.key)
}

func alterIndexDescriptor(b *testBundles) {
	publishContractBundle(b)
	b.index.Bundles[0].Descriptor += " "
	b.sign(b.key)
}

func signEmptyIndex(b *testBundles) { b.sign(b.key) }

func signNonIndex(b *testBundles) {
	b.files[rules.IndexFile] = []byte(`{}`)
	b.files[rules.IndexSigFile] = []byte(rules.Sign(b.key, []byte(`{}`)))
}

func closeServer(b *testBundles) { b.server.Close() }

// Every way Update can end, with the exact error text a user sees and the
// result fields the CLI reports. {server} and {host} stand for the test
// server's URL and address.
func TestUpdateContract(t *testing.T) {
	for _, test := range []struct {
		name    string
		setup   func(*testBundles)
		noIndex bool
		err     string
		id      string
		fresh   bool
		skipped []string
		network bool
	}{
		{name: "valid bundle", setup: publishContractBundle, id: contractBundle, fresh: true},
		{name: "already cached", setup: installContractBundle, id: contractBundle},
		{name: "no index", setup: func(*testBundles) {}, noIndex: true, err: "no rules index: pass --index or set TFPREFLIGHT_PACK_INDEX"},
		{name: "bad signature", setup: signIndexWithOtherKey, err: "rules index {server}/index.json: signature does not verify"},
		{name: "not an index", setup: signNonIndex, err: "rules index {server}/index.json is not a tfpreflight-pack-index/1 index"},
		{name: "empty index", setup: signEmptyIndex, err: "the index lists no bundle"},
		{name: "newer schema", setup: requireNewerSchema, skipped: []string{contractBundle}, err: "every bundle in the index needs a newer binary: the bundle needs a newer tfpreflight; update tfpreflight"},
		{name: "bad hash", setup: corruptContractArchive, id: contractBundle, err: "bundle 2026-10-13.1: the download's size or SHA-256 differs from the signed index"},
		{name: "descriptor differs", setup: alterIndexDescriptor, id: contractBundle, err: "bundle 2026-10-13.1: its descriptor differs from the signed index's"},
		{name: "network failure", setup: closeServer, network: true, err: `network: Get "{server}/index.json": dial tcp {host}: connect: connection refused`},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := newTestBundles(t)
			test.setup(b)
			index := b.server.URL + "/" + rules.IndexFile
			if test.noIndex {
				index = ""
			}
			result, err := Update(context.Background(), b.server.Client(), index)
			assertUpdateError(t, b, err, test.err, test.network)
			assertUpdateResult(t, result, test.id, test.fresh, test.skipped)
		})
	}
}

func assertUpdateError(t *testing.T, b *testBundles, err error, want string, network bool) {
	t.Helper()
	server, _ := url.Parse(b.server.URL)
	want = strings.NewReplacer("{server}", b.server.URL, "{host}", server.Host).Replace(want)
	got := ""
	if err != nil {
		got = err.Error()
	}
	if got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
	var networkErr *NetworkError
	if errors.As(err, &networkErr) != network {
		t.Errorf("network error = %v, want %v", !network, network)
	}
}

func assertUpdateResult(t *testing.T, result UpdateResult, id string, fresh bool, skipped []string) {
	t.Helper()
	if result.ID != id || result.Fresh != fresh || strings.Join(result.Skipped, " ") != strings.Join(skipped, " ") {
		t.Errorf("result = id %q fresh %v skipped %v, want id %q fresh %v skipped %v", result.ID, result.Fresh, result.Skipped, id, fresh, skipped)
	}
	wantDir := ""
	if id != "" {
		cache, err := CacheDir()
		if err != nil {
			t.Fatal(err)
		}
		wantDir = filepath.Join(cache, id)
	}
	if result.Dir != wantDir {
		t.Errorf("dir = %q, want %q", result.Dir, wantDir)
	}
	if (id != "") != (len(result.Versions) > 0) {
		t.Errorf("versions = %v for id %q", result.Versions, id)
	}
}

// A bundle whose signature and digests verify but whose pack does not
// materialize for a covered version is refused before it is installed.
func TestUpdateRefusesABundleThatDoesNotMaterialize(t *testing.T) {
	b := newTestBundles(t)
	b.publish(contractBundle, time.Now(), func(d *rules.BundleDescriptor, packDir string) {
		removeAValue(t, packDir, "aws/generated/quota-aws.json", d)
	})
	result, err := b.update()
	if err == nil || !strings.Contains(err.Error(), "bundle 2026-10-13.1: aws/generated/quota-aws-{provider_version}.json: ") || !strings.Contains(err.Error(), " has no value for ") {
		t.Fatalf("update error = %v", err)
	}
	if _, statErr := os.Stat(result.Dir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("refused bundle was installed at %s: %v", result.Dir, statErr)
	}
}

// removeAValue empties the first value field of a pack in the bundle being
// published, then updates its manifest digest so the bundle still verifies.
func removeAValue(t *testing.T, packDir, name string, d *rules.BundleDescriptor) {
	t.Helper()
	file := filepath.Join(packDir, filepath.FromSlash(name))
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	pack, err := rules.ReadRangePack(data)
	if err != nil {
		t.Fatal(err)
	}
	for i := range pack.Fields {
		if pack.Fields[i].Kind == rules.FieldValue {
			pack.Fields[i].Entries = nil
			break
		}
	}
	if data, err = pack.Encode(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data, 0o644); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(packDir, filepath.FromSlash(ManifestPath))
	var manifest rules.Manifest
	raw, _ := os.ReadFile(manifestPath)
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Files[name] = rules.Digest(data)
	raw, _ = json.Marshal(manifest)
	if err := os.WriteFile(manifestPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	d.ManifestSHA256 = rules.Digest(raw)
}
