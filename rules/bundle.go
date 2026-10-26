// The published pack bundle is the pack set as one signed archive; the signed
// index lists the bundles available. What is signed, and how it chains:   - the
// index (index.json) is signed whole (index.json.sig), so its bundles, their
// archive hashes and their descriptors cannot be altered without the key;   -
// each archive's SHA-256 is in the index;   - each bundle's descriptor
// (bundle.json) is signed (bundle.json.sig) and gives the SHA-256 of the pack
// set's manifest;   - the manifest gives the SHA-256 of every pack file.
//
// An index carries no expiry, so an older, validly signed index can be replayed;
// Select still prefers the newest bundle already in the cache. A cached bundle
// is checked again from its descriptor down on every run.

package rules

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Bundle and index formats.
const (
	BundleFormat = "tfpreflight-pack-bundle/1"
	IndexFormat  = "tfpreflight-pack-index/1"
)

// Files inside a bundle archive, beside the pack set's aws/ tree, and the
// index's files.
const (
	DescriptorFile = "bundle.json"
	SignatureFile  = "bundle.json.sig"
	IndexFile      = "index.json"
	IndexSigFile   = "index.json.sig"
)

// BundleDescriptor says what a bundle is. It is signed.
type BundleDescriptor struct {
	Format string `json:"format"`
	// ID is date-based, such as 2026-10-13.1.
	ID string `json:"id"`
	// CreatedAt is RFC 3339, UTC.
	CreatedAt string `json:"created_at"`
	// PackSchemaVersion is the pack format; a binary that reads another ignores
	// the bundle.
	PackSchemaVersion int      `json:"pack_schema_version"`
	Provider          string   `json:"provider"`
	Versions          []string `json:"versions"`
	// ManifestSHA256 is the hash of aws/manifest.json.
	ManifestSHA256 string `json:"manifest_sha256"`
}

// IndexEntry is one published bundle.
type IndexEntry struct {
	ID                string   `json:"id"`
	CreatedAt         string   `json:"created_at"`
	PackSchemaVersion int      `json:"pack_schema_version"`
	Versions          []string `json:"versions"`
	// URL is the archive's location, absolute or relative to the index.
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	// Descriptor is the bundle's signed descriptor, byte for byte, and Signature
	// its signature.
	Descriptor string `json:"descriptor"`
	Signature  string `json:"signature"`
}

// Index lists published bundles, newest first.
type Index struct {
	Format  string       `json:"format"`
	Bundles []IndexEntry `json:"bundles"`
}

// ErrNeedsNewerBinary marks a bundle whose pack format this binary cannot
// read.
var ErrNeedsNewerBinary = errors.New("the bundle needs a newer tfpreflight; update tfpreflight")

// Sign returns the base64 signature of data.
func Sign(key ed25519.PrivateKey, data []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, data))
}

// Verify checks a base64 signature of data.
func Verify(key ed25519.PublicKey, data []byte, signature string) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signature))
	if err != nil {
		return fmt.Errorf("signature is not base64: %w", err)
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, data, raw) {
		return errors.New("signature does not verify")
	}
	return nil
}

// ParsePublicKey reads a base64 Ed25519 public key.
func ParsePublicKey(text string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("not a base64 Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

// ParsePrivateKey reads a base64 Ed25519 seed (32 bytes) or private key
// (64 bytes).
func ParsePrivateKey(text string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil {
		return nil, errors.New("signing key is not base64")
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	}
	return nil, errors.New("signing key is not an Ed25519 seed or private key")
}

// CheckDescriptor checks a descriptor's signature and that this binary reads its
// pack format.
func CheckDescriptor(key ed25519.PublicKey, data []byte, signature string) (BundleDescriptor, error) {
	var d BundleDescriptor
	if err := Verify(key, data, signature); err != nil {
		return d, fmt.Errorf("bundle descriptor: %w", err)
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return d, fmt.Errorf("bundle descriptor: %w", err)
	}
	if d.Format != BundleFormat {
		return d, fmt.Errorf("bundle format %q: %w", d.Format, ErrNeedsNewerBinary)
	}
	if d.PackSchemaVersion > SchemaVersion {
		return d, fmt.Errorf("pack schema %d, this tfpreflight reads %d: %w", d.PackSchemaVersion, SchemaVersion, ErrNeedsNewerBinary)
	}
	if d.PackSchemaVersion < SchemaVersion {
		return d, fmt.Errorf("pack schema %d is older than %d, which this tfpreflight reads", d.PackSchemaVersion, SchemaVersion)
	}
	return d, nil
}

// WriteArchive writes a pack set directory and its descriptor and signature as a
// gzipped tar, deterministically: sorted paths, fixed modes and times.
func WriteArchive(w io.Writer, packDir string, descriptor []byte, signature string) error {
	files := map[string][]byte{DescriptorFile: descriptor, SignatureFile: []byte(signature + "\n")}
	err := filepath.WalkDir(filepath.Join(packDir, "aws"), func(p string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		relative, err := filepath.Rel(packDir, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(relative)] = data
		return nil
	})
	if err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	zw, err := gzip.NewWriterLevel(w, gzip.BestCompression)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(zw)
	epoch := time.Unix(0, 0).UTC()
	for _, name := range names {
		header := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(files[name])), ModTime: epoch, Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if _, err := tw.Write(files[name]); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return zw.Close()
}

// maxArchiveFile bounds one file in an archive; the largest pack is a few MB.
const maxArchiveFile = 256 << 20

// ExtractArchive unpacks a bundle archive into dir. Any entry but a regular file
// under aws/, the descriptor or its signature fails the whole extraction.
func ExtractArchive(data []byte, dir string) error {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	tr := tar.NewReader(zr)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := path.Clean(header.Name)
		allowed := name == DescriptorFile || name == SignatureFile || strings.HasPrefix(name, "aws/")
		if header.Typeflag != tar.TypeReg || !allowed || strings.Contains(name, "..") || path.IsAbs(name) {
			return fmt.Errorf("bundle archive holds an unexpected entry %q", header.Name)
		}
		if header.Size > maxArchiveFile {
			return fmt.Errorf("bundle archive entry %q is too large", name)
		}
		target := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		content, err := io.ReadAll(io.LimitReader(tr, maxArchiveFile))
		if err != nil {
			return err
		}
		if err := os.WriteFile(target, content, 0o644); err != nil {
			return err
		}
	}
}
