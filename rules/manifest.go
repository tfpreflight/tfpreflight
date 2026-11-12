package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// SchemaVersion is the pack format version, and the one the packs are built
// in. Version 2 holds range packs: one file per pack kind, covering many
// provider versions. Version 3 is version 2 plus what beta.7 reads that earlier
// versions do not: listing lookups, fixed and page inputs, and the create
// semantics duplicate-error-listed.
//
// The number is the gate for older binaries. A binary skips a bundle whose
// schema is newer than it reads and keeps the newest one it can read, so a
// bundle with those rules is never seen by a binary that cannot run them. Every
// release that reads a new pack feature must raise it.
const SchemaVersion = 3

// OldestSchemaVersion is the oldest pack format this binary still reads.
// Version 3 differs from 2 only by what a pack may contain, so a version 2
// bundle, such as one cached before an upgrade, is read as it always was.
const OldestSchemaVersion = 2

// ManifestPath is where a set's manifest lives.
const ManifestPath = "aws/manifest.json"

// Manifest names every file in a pack set and its SHA-256.
type Manifest struct {
	SchemaVersion int    `json:"schema_version"`
	Provider      string `json:"provider"`
	// Files maps a path relative to the set root, such as
	// aws/generated/aws-6.64.0.json, to the hex SHA-256 of its bytes.
	Files map[string]string `json:"files"`
	// Versions lists every provider version the set covers, oldest first. Every
	// range pack covers exactly these.
	Versions []string `json:"versions"`
}

// RangePackPath is the range pack standing for a per-version file name:
// aws/dependency/rules.json for aws/dependency/rules-{provider_version}.json.
func RangePackPath(name string) string {
	return strings.Replace(name, "-"+VersionToken, "", 1)
}

// Digest is the manifest's hash of a file.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
