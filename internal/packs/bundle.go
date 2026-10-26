package packs

// Choosing the pack set a run uses, and tfpreflight update. See rules/bundle.go
// for the bundle format and what is signed.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/tfpreflight/tfpreflight/rules"
)

// Where a pack set came from.
const (
	OriginEmbedded = "embedded"
	OriginCache    = "cache"
	OriginDir      = "dir"
)

// Info describes a pack set.
type Info struct {
	// ID is the bundle id, "embedded" for the built-in packs, or "dir" for
	// --pack-dir.
	ID       string
	Origin   string
	Location string
	Versions []string
}

// Info describes the set.
func (s *Set) Info() Info {
	return Info{ID: s.id, Origin: s.origin, Location: s.location, Versions: s.Versions()}
}

// CacheEnv overrides where bundles are cached.
const CacheEnv = "TFPREFLIGHT_PACK_CACHE"

// IndexEnv names the index tfpreflight update reads.
const IndexEnv = "TFPREFLIGHT_PACK_INDEX"

// DefaultIndex is the index tfpreflight update reads when neither --index nor
// TFPREFLIGHT_PACK_INDEX names one. Release builds set it with -ldflags -X.
var DefaultIndex = ""

// CacheDir is where downloaded bundles live, one directory per bundle.
func CacheDir() (string, error) {
	if dir := os.Getenv(CacheEnv); dir != "" {
		return dir, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "tfpreflight", "packs"), nil
}

func publicKey() (ed25519.PublicKey, error) { return rules.ParsePublicKey(signingKey) }

// OpenBundle opens a downloaded bundle, checking it from its signed descriptor
// down: the signature, the pack format, the manifest's hash, then every file the
// manifest names.
func OpenBundle(dir string) (*Set, rules.BundleDescriptor, error) {
	var descriptor rules.BundleDescriptor
	key, err := publicKey()
	if err != nil {
		return nil, descriptor, err
	}
	data, err := os.ReadFile(filepath.Join(dir, rules.DescriptorFile))
	if err != nil {
		return nil, descriptor, err
	}
	signature, err := os.ReadFile(filepath.Join(dir, rules.SignatureFile))
	if err != nil {
		return nil, descriptor, err
	}
	if descriptor, err = rules.CheckDescriptor(key, data, string(signature)); err != nil {
		return nil, descriptor, err
	}
	manifest, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(ManifestPath)))
	if err != nil {
		return nil, descriptor, err
	}
	if rules.Digest(manifest) != descriptor.ManifestSHA256 {
		return nil, descriptor, errors.New("the manifest's hash differs from the signed descriptor's")
	}
	set, err := Open(os.DirFS(dir), "cache "+descriptor.ID)
	if err != nil {
		return nil, descriptor, err
	}
	if !slices.Equal(set.versions, descriptor.Versions) {
		return nil, descriptor, errors.New("the manifest's versions differ from the signed descriptor's")
	}
	set.id, set.origin, set.location = descriptor.ID, OriginCache, dir
	return set, descriptor, nil
}

type cachedBundle struct {
	set        *Set
	descriptor rules.BundleDescriptor
	dir        string
}

// cachedBundles opens every cached bundle, newest first. One that fails any
// check is left out, with a warning.
func cachedBundles() ([]cachedBundle, []string) {
	dir, err := CacheDir()
	if err != nil {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil
	}
	var valid []cachedBundle
	var warnings []string
	for _, entry := range entries {
		if !entry.IsDir() || osJunk(entry.Name()) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		set, descriptor, err := OpenBundle(path)
		if err != nil {
			if errors.Is(err, rules.ErrNeedsNewerBinary) {
				warnings = append(warnings, fmt.Sprintf("ignoring cached rules bundle %s: %v", entry.Name(), err))
			} else {
				warnings = append(warnings, fmt.Sprintf("ignoring cached rules bundle %s: it fails its checks (%v); it will not be used", entry.Name(), err))
			}
			continue
		}
		valid = append(valid, cachedBundle{set, descriptor, path})
	}
	sort.SliceStable(valid, func(i, j int) bool { return valid[i].descriptor.CreatedAt > valid[j].descriptor.CreatedAt })
	return valid, warnings
}

func newest(versions []string) string {
	if len(versions) == 0 {
		return ""
	}
	return versions[len(versions)-1]
}

// Select chooses the pack set a run uses: --pack-dir, else the newest valid
// cached bundle, else the built-in packs. A cached bundle older than the built-
// in packs, as after upgrading tfpreflight, is passed over. Warnings say what
// was ignored and why.
func Select(packDir string) (*Set, []string, error) {
	if packDir != "" {
		set, err := Dir(packDir)
		return set, nil, err
	}
	embedded, err := Embedded()
	if err != nil {
		return nil, nil, err
	}
	bundles, warnings := cachedBundles()
	if len(bundles) > 0 {
		cached := bundles[0]
		if rules.CompareVersions(newest(cached.set.versions), newest(embedded.versions)) < 0 {
			warnings = append(warnings, fmt.Sprintf("cached rules bundle %s covers up to AWS provider %s; this tfpreflight's built-in rules cover up to %s, so they are used. Run tfpreflight update.",
				cached.descriptor.ID, newest(cached.set.versions), newest(embedded.versions)))
			return embedded, warnings, nil
		}
		return cached.set, warnings, nil
	}
	return embedded, warnings, nil
}

// UpdateResult says what tfpreflight update did.
type UpdateResult struct {
	ID       string
	Versions []string
	// Fresh is false when the cache already held the newest bundle.
	Fresh bool
	// Skipped lists newer bundles this binary cannot read.
	Skipped []string
	Dir     string
}

// NetworkError is an update that could not reach the index or bundle.
type NetworkError struct{ Err error }

// Error returns the network failure message.
func (e *NetworkError) Error() string { return "network: " + e.Err.Error() }

// Unwrap returns the underlying network failure.
func (e *NetworkError) Unwrap() error { return e.Err }

// Update installs the newest bundle in the index that this binary can read,
// after checking the index's signature, the archive's size and hash, and the
// bundle itself. The bundle before it stays as a fallback; older ones are
// removed.
func Update(ctx context.Context, client *http.Client, index string) (UpdateResult, error) {
	var update UpdateResult
	if index == "" {
		return update, fmt.Errorf("no rules index: pass --index or set %s", IndexEnv)
	}
	list, err := fetchIndex(ctx, client, index)
	if err != nil {
		return update, err
	}
	chosen, skipped := chooseBundle(list)
	update.Skipped = skipped
	if chosen == nil {
		if len(update.Skipped) > 0 {
			return update, fmt.Errorf("every bundle in the index needs a newer binary: %w", rules.ErrNeedsNewerBinary)
		}
		return update, errors.New("the index lists no bundle")
	}
	update.ID, update.Versions = chosen.ID, chosen.Versions
	cache, err := CacheDir()
	if err != nil {
		return update, err
	}
	update.Dir = filepath.Join(cache, chosen.ID)
	if _, descriptor, err := OpenBundle(update.Dir); err == nil && descriptor.ID == chosen.ID {
		prune(chosen.ID)
		return update, nil
	}
	if err := install(ctx, client, resolve(index, chosen.URL), chosen, cache, update.Dir); err != nil {
		return update, err
	}
	update.Fresh = true
	prune(chosen.ID)
	return update, nil
}

// fetchIndex downloads the pack index and accepts it only if its signature
// verifies against the built-in key.
func fetchIndex(ctx context.Context, client *http.Client, index string) (rules.Index, error) {
	key, err := publicKey()
	if err != nil {
		return rules.Index{}, err
	}
	indexData, err := get(ctx, client, index, maxIndexSize)
	if err != nil {
		return rules.Index{}, err
	}
	indexSig, err := get(ctx, client, resolve(index, rules.IndexSigFile), maxSignatureSize)
	if err != nil {
		return rules.Index{}, err
	}
	if err := rules.Verify(key, indexData, string(indexSig)); err != nil {
		return rules.Index{}, fmt.Errorf("rules index %s: %w", index, err)
	}
	var list rules.Index
	if err := json.Unmarshal(indexData, &list); err != nil || list.Format != rules.IndexFormat {
		return rules.Index{}, fmt.Errorf("rules index %s is not a %s index", index, rules.IndexFormat)
	}
	return list, nil
}

// chooseBundle picks the first bundle whose pack schema this binary reads, and
// lists the newer-schema bundles before it.
func chooseBundle(list rules.Index) (*rules.IndexEntry, []string) {
	var skipped []string
	for i := range list.Bundles {
		entry := &list.Bundles[i]
		if entry.PackSchemaVersion > rules.SchemaVersion {
			skipped = append(skipped, entry.ID)
			continue
		}
		if entry.PackSchemaVersion == rules.SchemaVersion {
			return entry, skipped
		}
	}
	return nil, skipped
}

// install downloads a bundle, checks it against the signed index, and moves it
// into place only once every check has passed.
func install(ctx context.Context, client *http.Client, location string, chosen *rules.IndexEntry, cache, dir string) error {
	// The signed index gives the archive's size, so nothing larger is read.
	archive, err := get(ctx, client, location, chosen.Size)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(archive)
	if int64(len(archive)) != chosen.Size || hex.EncodeToString(sum[:]) != chosen.SHA256 {
		return fmt.Errorf("bundle %s: the download's size or SHA-256 differs from the signed index", chosen.ID)
	}
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(cache, ".download-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	if err := rules.ExtractArchive(archive, staging); err != nil {
		return fmt.Errorf("bundle %s: %w", chosen.ID, err)
	}
	if descriptor, err := os.ReadFile(filepath.Join(staging, rules.DescriptorFile)); err != nil || string(descriptor) != chosen.Descriptor {
		return fmt.Errorf("bundle %s: its descriptor differs from the signed index's", chosen.ID)
	}
	set, _, err := OpenBundle(staging)
	if err == nil {
		err = set.ValidateMaterialized()
	}
	if err != nil {
		return fmt.Errorf("bundle %s: %w", chosen.ID, err)
	}
	_ = os.RemoveAll(dir)
	return os.Rename(staging, dir)
}

// prune keeps the current bundle and the newest valid one before it.
func prune(current string) {
	bundles, _ := cachedBundles()
	kept := 0
	for _, b := range bundles {
		if b.descriptor.ID == current {
			continue
		}
		if kept < 1 {
			kept++
			continue
		}
		_ = os.RemoveAll(b.dir)
	}
}

// resolve gives a location relative to the index's.
func resolve(index, ref string) string {
	if u, err := url.Parse(ref); err == nil && u.IsAbs() {
		return ref
	}
	if base, err := url.Parse(index); err == nil && base.IsAbs() && base.Scheme != "file" {
		if r, err := url.Parse(ref); err == nil {
			return base.ResolveReference(r).String()
		}
	}
	dir := strings.TrimPrefix(index, "file://")
	return filepath.Join(filepath.Dir(dir), ref)
}

// An index lists a few bundles, and a signature is one base64 Ed25519 signature.
const (
	maxIndexSize     = 1 << 20
	maxSignatureSize = 1 << 10
)

// get reads an http(s) URL, a file:// URL or a path, failing beyond limit bytes.
// A failed connection or a missing file is a NetworkError.
func get(ctx context.Context, client *http.Client, location string, limit int64) ([]byte, error) {
	if !strings.HasPrefix(location, "http://") && !strings.HasPrefix(location, "https://") {
		file, err := os.Open(strings.TrimPrefix(location, "file://"))
		if errors.Is(err, os.ErrNotExist) {
			return nil, &NetworkError{err}
		}
		if err != nil {
			return nil, err
		}
		defer func() { _ = file.Close() }()
		return readLimited(file, location, limit)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, &NetworkError{err}
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, &NetworkError{fmt.Errorf("%s: HTTP %d", location, response.StatusCode)}
	}
	return readLimited(response.Body, location, limit)
}

// readLimited fails beyond limit bytes rather than truncating: a truncated read
// would only fail later, as a confusing hash mismatch.
func readLimited(r io.Reader, location string, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", location, limit)
	}
	return data, nil
}
