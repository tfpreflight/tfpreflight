package packs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tfpreflight/tfpreflight/rules"
)

// shippedPacks is the pack set the binary embeds.
const shippedPacks = "../../packs"

// fixturePacks is the shipped pack set cut down to its newest version, built
// once by TestMain. The update tests exercise signing, hashing and caching,
// which do not need all 60 versions; publishing and installing the full set
// in every test is what made them slow. fixtureVersion is that version.
var fixturePacks, fixtureVersion string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "tfpreflight-pack-fixture-")
	if err == nil {
		err = buildFixture(dir)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "build the pack fixture:", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func buildFixture(dir string) error {
	if err := os.CopyFS(dir, os.DirFS(shippedPacks)); err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(dir, ManifestPath))
	if err != nil {
		return err
	}
	var manifest rules.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return err
	}
	newest := manifest.Versions[len(manifest.Versions)-1]
	if _, err := rebuild(dir, newest, rules.BundleDescriptor{}); err != nil {
		return err
	}
	fixturePacks, fixtureVersion = dir, newest
	return nil
}

// The shipped pack set, all of it, installs as a bundle and is used. The
// other update tests use the cut-down fixture.
func TestShippedPackSetInstallsAsABundle(t *testing.T) {
	if testing.Short() {
		t.Skip("installs and materializes every shipped version")
	}
	b := newTestBundles(t)
	b.publishFrom(shippedPacks, "2026-10-13.1", time.Now(), nil)
	if result, err := b.update(); err != nil || !result.Fresh {
		t.Fatalf("update = %+v, %v", result, err)
	}
	set, warnings, err := Select("")
	if err != nil || len(warnings) != 0 || set.Info().Origin != OriginCache {
		t.Fatalf("select: %+v %v %v", set.Info(), warnings, err)
	}
	embedded, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(set.Versions(), embedded.Versions()) {
		t.Fatalf("installed versions %v, want the shipped %v", set.Versions(), embedded.Versions())
	}
}

// testBundles signs bundles with a key of its own, which the test makes the
// trusted one, and serves them from a test server.
type testBundles struct {
	t      *testing.T
	key    ed25519.PrivateKey
	files  map[string][]byte
	server *httptest.Server
	index  rules.Index
}

func newTestBundles(t *testing.T) *testBundles {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trusted := signingKey
	signingKey = base64.StdEncoding.EncodeToString(public)
	t.Cleanup(func() { signingKey = trusted })
	t.Setenv(CacheEnv, t.TempDir())
	b := &testBundles{t: t, key: private, files: map[string][]byte{}, index: rules.Index{Format: rules.IndexFormat}}
	b.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, ok := b.files[strings.TrimPrefix(r.URL.Path, "/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}))
	t.Cleanup(b.server.Close)
	return b
}

// publish adds a bundle of the fixture pack set, changed by edit, to the
// index in the same shape as the published pack service.
func (b *testBundles) publish(id string, created time.Time, edit func(d *rules.BundleDescriptor, packDir string)) {
	b.t.Helper()
	b.publishFrom(fixturePacks, id, created, edit)
}

// publishFrom publishes a bundle of the pack set in source.
func (b *testBundles) publishFrom(source, id string, created time.Time, edit func(d *rules.BundleDescriptor, packDir string)) {
	b.t.Helper()
	packDir := b.t.TempDir()
	if err := os.CopyFS(packDir, os.DirFS(source)); err != nil {
		b.t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(packDir, ManifestPath))
	if err != nil {
		b.t.Fatal(err)
	}
	var m rules.Manifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		b.t.Fatal(err)
	}
	d := rules.BundleDescriptor{
		Format: rules.BundleFormat, ID: id, CreatedAt: created.UTC().Format(time.RFC3339),
		PackSchemaVersion: m.SchemaVersion, Provider: "aws", Versions: m.Versions, ManifestSHA256: rules.Digest(manifest),
	}
	if edit != nil {
		edit(&d, packDir)
	}
	descriptor, _ := json.Marshal(d)
	signature := rules.Sign(b.key, descriptor)
	var archive bytes.Buffer
	if err := rules.WriteArchive(&archive, packDir, descriptor, signature); err != nil {
		b.t.Fatal(err)
	}
	name := "tfpreflight-packs-" + id + ".tar.gz"
	b.files[name] = archive.Bytes()
	sum := sha256.Sum256(archive.Bytes())
	b.index.Bundles = append([]rules.IndexEntry{{
		ID: id, CreatedAt: d.CreatedAt, PackSchemaVersion: d.PackSchemaVersion, Versions: d.Versions,
		URL: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(archive.Len()), Descriptor: string(descriptor), Signature: signature,
	}}, b.index.Bundles...)
	b.sign(b.key)
}

func (b *testBundles) sign(key ed25519.PrivateKey) {
	data, _ := json.Marshal(b.index)
	b.files[rules.IndexFile] = data
	b.files[rules.IndexSigFile] = []byte(rules.Sign(key, data))
}

func (b *testBundles) update() (UpdateResult, error) {
	return Update(context.Background(), b.server.Client(), b.server.URL+"/"+rules.IndexFile)
}

func TestValidBundleIsInstalledAndPreferredOverEmbedded(t *testing.T) {
	b := newTestBundles(t)
	b.publish("2026-10-13.1", time.Now(), nil)
	result, err := b.update()
	if err != nil || !result.Fresh || result.ID != "2026-10-13.1" {
		t.Fatalf("update = %+v, %v", result, err)
	}
	set, warnings, err := Select("")
	if err != nil || len(warnings) != 0 {
		t.Fatalf("select: %v %v", warnings, err)
	}
	if info := set.Info(); info.Origin != OriginCache || info.ID != "2026-10-13.1" {
		t.Fatalf("in use: %+v", info)
	}
	if _, err := set.ReadFile("aws/dependency/rules-" + fixtureVersion + ".json"); err != nil {
		t.Fatal(err)
	}
	// A second update finds nothing newer.
	if again, err := b.update(); err != nil || again.Fresh {
		t.Fatalf("second update = %+v, %v", again, err)
	}
	// A newer bundle replaces it; the one before stays as the fallback.
	b.publish("2026-10-14.1", time.Now().Add(time.Hour), nil)
	if _, err := b.update(); err != nil {
		t.Fatal(err)
	}
	b.publish("2026-10-15.1", time.Now().Add(2*time.Hour), nil)
	if _, err := b.update(); err != nil {
		t.Fatal(err)
	}
	cache, _ := CacheDir()
	entries, _ := os.ReadDir(cache)
	var kept []string
	for _, e := range entries {
		kept = append(kept, e.Name())
	}
	if strings.Join(kept, " ") != "2026-10-14.1 2026-10-15.1" {
		t.Fatalf("cache holds %v, want the newest and the one before", kept)
	}
}

func TestBadSignatureIsNeverUsed(t *testing.T) {
	b := newTestBundles(t)
	b.publish("2026-10-13.1", time.Now(), nil)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	b.sign(other)
	if _, err := b.update(); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("an index signed with another key was accepted: %v", err)
	}
	// A cached bundle whose descriptor was altered after signing.
	b.sign(b.key)
	result, err := b.update()
	if err != nil {
		t.Fatal(err)
	}
	descriptor := filepath.Join(result.Dir, rules.DescriptorFile)
	data, _ := os.ReadFile(descriptor)
	if err := os.WriteFile(descriptor, bytes.Replace(data, []byte(`"aws"`), []byte(`"AWS"`), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	set, warnings, err := Select("")
	if err != nil || set.Info().Origin != OriginEmbedded || len(warnings) != 1 || !strings.Contains(warnings[0], "signature does not verify") {
		t.Fatalf("tampered bundle: %+v %v %v", set.Info(), warnings, err)
	}
}

func TestBadHashIsNeverUsed(t *testing.T) {
	b := newTestBundles(t)
	b.publish("2026-10-13.1", time.Now(), nil)
	name := "tfpreflight-packs-2026-10-13.1.tar.gz"
	good := b.files[name]
	b.files[name] = flipLastByte(good)
	if _, err := b.update(); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("an archive whose hash differs from the index was accepted: %v", err)
	}
	b.files[name] = good
	result, err := b.update()
	if err != nil {
		t.Fatal(err)
	}
	// A cached pack file changed after download.
	pack := filepath.Join(result.Dir, "aws", "dependency", "rules.json")
	data, _ := os.ReadFile(pack)
	if err := os.WriteFile(pack, append(data, ' '), 0o644); err != nil {
		t.Fatal(err)
	}
	set, warnings, err := Select("")
	if err != nil || set.Info().Origin != OriginEmbedded || len(warnings) != 1 || !strings.Contains(warnings[0], "manifest says") {
		t.Fatalf("altered pack: %+v %v %v", set.Info(), warnings, err)
	}
}

func TestBundleNeedingANewerBinaryIsIgnored(t *testing.T) {
	b := newTestBundles(t)
	b.publish("2026-10-13.1", time.Now(), func(d *rules.BundleDescriptor, _ string) { d.PackSchemaVersion = rules.SchemaVersion + 1 })
	b.index.Bundles[0].PackSchemaVersion = rules.SchemaVersion + 1
	b.sign(b.key)
	result, err := b.update()
	if !errors.Is(err, rules.ErrNeedsNewerBinary) || len(result.Skipped) != 1 {
		t.Fatalf("update = %+v, %v", result, err)
	}
	// A readable older bundle behind it is used instead.
	b.publish("2026-10-12.1", time.Now().Add(-time.Hour), nil)
	b.index.Bundles[0], b.index.Bundles[1] = b.index.Bundles[1], b.index.Bundles[0]
	b.sign(b.key)
	if result, err = b.update(); err != nil || result.ID != "2026-10-12.1" || len(result.Skipped) != 1 {
		t.Fatalf("update = %+v, %v", result, err)
	}
}

func TestOfflineKeepsThePacksInUse(t *testing.T) {
	b := newTestBundles(t)
	b.server.Close()
	_, err := b.update()
	var network *NetworkError
	if !errors.As(err, &network) {
		t.Fatalf("offline update: %v, want a network error", err)
	}
	set, warnings, err := Select("")
	if err != nil || set.Info().Origin != OriginEmbedded || len(warnings) != 0 {
		t.Fatalf("offline select: %+v %v %v", set.Info(), warnings, err)
	}
}

func TestUpdateFollowsHTTPSRedirectsAndChecksFinalContent(t *testing.T) {
	b := newTestBundles(t)
	b.publish("2026-10-13.1", time.Now(), nil)
	b.server.Close()

	redirects := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const redirectPrefix = "/redirect/"
		const finalPrefix = "/final/"
		switch {
		case strings.HasPrefix(r.URL.Path, redirectPrefix):
			redirects++
			http.Redirect(w, r, finalPrefix+strings.TrimPrefix(r.URL.Path, redirectPrefix), http.StatusFound)
		case strings.HasPrefix(r.URL.Path, finalPrefix):
			data, ok := b.files[strings.TrimPrefix(r.URL.Path, finalPrefix)]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(data)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	index := server.URL + "/redirect/" + rules.IndexFile
	result, err := Update(context.Background(), server.Client(), index)
	if err != nil || !result.Fresh {
		t.Fatalf("redirected update = %+v, %v", result, err)
	}
	if redirects != 3 {
		t.Fatalf("followed %d redirects, want index, signature, and archive", redirects)
	}

	// A redirect changes only where bytes come from. Verification still uses
	// the signed index's hash for the final archive response.
	if err := os.RemoveAll(result.Dir); err != nil {
		t.Fatal(err)
	}
	archive := "tfpreflight-packs-2026-10-13.1.tar.gz"
	b.files[archive] = flipLastByte(b.files[archive])
	if _, err := Update(context.Background(), server.Client(), index); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("altered final redirect content was accepted: %v", err)
	}
}

// After tfpreflight itself is upgraded, a cached bundle that covers no
// version as new as the embedded packs is passed over for them.
func TestStaleCachedBundleFallsBackToEmbedded(t *testing.T) {
	b := newTestBundles(t)
	b.publishFrom(shippedPacks, "2026-10-13.1", time.Now(), func(d *rules.BundleDescriptor, packDir string) {
		// A bundle covering only the oldest embedded version.
		cut, err := rebuild(packDir, d.Versions[0], *d)
		if err != nil {
			t.Fatal(err)
		}
		*d = cut
	})
	if _, err := b.update(); err != nil {
		t.Fatal(err)
	}
	set, warnings, err := Select("")
	if err != nil || set.Info().Origin != OriginEmbedded || len(warnings) != 1 || !strings.Contains(warnings[0], "Run tfpreflight update") {
		t.Fatalf("stale cache: %+v %v %v", set.Info(), warnings, err)
	}
}

// rebuild cuts a pack set down to one version.
func rebuild(packDir, version string, d rules.BundleDescriptor) (rules.BundleDescriptor, error) {
	files, _ := filepath.Glob(filepath.Join(packDir, "aws", "*", "*.json"))
	manifest := rules.Manifest{SchemaVersion: rules.SchemaVersion, Provider: "aws", Files: map[string]string{}, Versions: []string{version}}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return d, err
		}
		if filepath.Base(file) == "manifest.json" {
			continue
		}
		if rules.IsRangePack(data) {
			if data, err = cutRangePack(file, data, version); err != nil {
				return d, err
			}
		}
		relative, _ := filepath.Rel(packDir, file)
		manifest.Files[filepath.ToSlash(relative)] = rules.Digest(data)
	}
	data, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(packDir, ManifestPath), data, 0o644); err != nil {
		return d, err
	}
	d.Versions, d.ManifestSHA256 = manifest.Versions, rules.Digest(data)
	return d, nil
}

// cutRangePack rewrites a range pack file to cover only version and returns
// its new bytes. It keeps each field and entry that holds for version, so the
// cut pack materializes that version exactly as the full pack did.
func cutRangePack(file string, data []byte, version string) ([]byte, error) {
	pack, err := rules.ReadRangePack(data)
	if err != nil {
		return nil, err
	}
	want, err := pack.Materialize(version)
	if err != nil {
		return nil, err
	}
	position := map[string]int{}
	for i, v := range pack.Versions {
		position[v] = i
	}
	holds := func(ranges []rules.VersionRange) bool {
		for _, r := range ranges {
			if position[r[0]] <= position[version] && position[version] <= position[r[1]] {
				return true
			}
		}
		return false
	}
	only := []rules.VersionRange{{version, version}}
	var fields []rules.RangeField
	for _, field := range pack.Fields {
		if holds(field.Present) {
			fields = append(fields, cutField(field, version, only, holds))
		}
	}
	pack.Versions, pack.Fields = []string{version}, fields
	got, err := pack.Materialize(version)
	if err != nil {
		return nil, fmt.Errorf("cut %s: %w", file, err)
	}
	if !bytes.Equal(got, want) {
		return nil, fmt.Errorf("cut %s does not materialize %s as the full pack did", file, version)
	}
	if data, err = pack.Encode(); err != nil {
		return nil, err
	}
	return data, os.WriteFile(file, data, 0o644)
}

// cutField keeps the entries that hold for version, renumbering the
// version's explicit order to match.
func cutField(field rules.RangeField, version string, only []rules.VersionRange, holds func([]rules.VersionRange) bool) rules.RangeField {
	renumbered := map[int]int{}
	var entries []rules.RangeEntry
	for i, entry := range field.Entries {
		if holds(entry.Versions) {
			renumbered[i] = len(entries)
			entry.Versions = only
			entries = append(entries, entry)
		}
	}
	order, explicit := field.Order[version]
	field.Present, field.Entries, field.Order = only, entries, nil
	if explicit {
		cut := make([]int, len(order))
		for j, i := range order {
			cut[j] = renumbered[i]
		}
		field.Order = map[string][]int{version: cut}
	}
	return field
}

func TestEmbeddedWhenNothingIsCached(t *testing.T) {
	newTestBundles(t)
	set, warnings, err := Select("")
	if err != nil || set.Info().Origin != OriginEmbedded || set.Info().ID != OriginEmbedded || len(warnings) != 0 {
		t.Fatalf("empty cache: %+v %v %v", set.Info(), warnings, err)
	}
	dir, _, err := Select("../../packs")
	if err != nil || dir.Info().Origin != OriginDir {
		t.Fatalf("--pack-dir: %+v %v", dir.Info(), err)
	}
}

// flipLastByte is data with its size kept and its hash changed.
func flipLastByte(data []byte) []byte {
	changed := append([]byte(nil), data...)
	changed[len(changed)-1] ^= 0xff
	return changed
}

// Nothing larger than its limit is read: an index or signature beyond a
// fixed size, or an archive beyond the size the signed index gives.
func TestUpdateRefusesOversizedDownloads(t *testing.T) {
	for name, tc := range map[string]struct {
		file string
		grow func(b *testBundles) []byte
		want string
	}{
		"index": {rules.IndexFile, func(b *testBundles) []byte {
			return append(b.files[rules.IndexFile], bytes.Repeat([]byte(" "), maxIndexSize)...)
		}, "index.json is larger than 1048576 bytes"},
		"signature": {rules.IndexSigFile, func(b *testBundles) []byte {
			return append(b.files[rules.IndexSigFile], bytes.Repeat([]byte(" "), maxSignatureSize)...)
		}, "index.json.sig is larger than 1024 bytes"},
		"archive": {"tfpreflight-packs-2026-10-13.1.tar.gz", func(b *testBundles) []byte {
			return append(b.files["tfpreflight-packs-2026-10-13.1.tar.gz"], 0)
		}, ".tar.gz is larger than"},
	} {
		t.Run(name, func(t *testing.T) {
			b := newTestBundles(t)
			b.publish("2026-10-13.1", time.Now(), nil)
			b.files[tc.file] = tc.grow(b)
			_, err := b.update()
			var network *NetworkError
			if err == nil || !strings.Contains(err.Error(), tc.want) || errors.As(err, &network) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// Files an operating system adds by itself, such as Finder's .DS_Store, are
// skipped wherever rules are read from, as go:embed skips them in the built-in
// rules. Every file the manifest lists is still required and checked, and any
// other unlisted file still fails the set.
func TestOSJunkIsIgnoredButEveryListedFileIsChecked(t *testing.T) {
	b := newTestBundles(t)
	b.publish("2026-10-13.1", time.Now(), nil)
	if _, err := b.update(); err != nil {
		t.Fatal(err)
	}
	cache, err := CacheDir()
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(cache, "2026-10-13.1")
	for _, junk := range []string{
		filepath.Join(cache, ".DS_Store"),
		filepath.Join(cache, "__MACOSX", "2026-10-13.1", "._bundle.json"),
		filepath.Join(bundle, ".DS_Store"),
		filepath.Join(bundle, "aws", ".DS_Store"),
		filepath.Join(bundle, "aws", "generated", "._aws.json"),
		filepath.Join(bundle, "aws", "generated", "Thumbs.db"),
	} {
		if err := os.MkdirAll(filepath.Dir(junk), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(junk, []byte("junk"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	set, warnings, err := Select("")
	if err != nil || len(warnings) != 0 || set.Info().ID != "2026-10-13.1" {
		t.Fatalf("cache with OS junk: %v, warnings %v, %v", set.Info(), warnings, err)
	}
	if _, _, err := Select(bundle); err != nil {
		t.Fatalf("--pack-dir with OS junk: %v", err)
	}

	unlisted := filepath.Join(bundle, "aws", "generated", "extra.json")
	if err := os.WriteFile(unlisted, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Select(bundle); err == nil || !strings.Contains(err.Error(), "aws/generated/extra.json is not in the manifest") {
		t.Fatalf("an unlisted file that is not junk was accepted: %v", err)
	}
	if err := os.Remove(unlisted); err != nil {
		t.Fatal(err)
	}
	listed := filepath.Join(bundle, "aws", "generated", "aws.json")
	if err := os.WriteFile(listed, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Select(bundle); err == nil || !strings.Contains(err.Error(), "aws/generated/aws.json has SHA-256") {
		t.Fatalf("a changed listed file was accepted: %v", err)
	}
}
