// Package packs is where the runtime reads knowledge packs from.
//
// A pack set is a directory tree whose manifest, aws/manifest.json, names every
// file and its SHA-256. A set is validated in full when it is opened: an unknown
// schema, a missing, altered or unlisted file makes it unusable. A bad set never
// falls back to another; the caller reports a tool failure.
package packs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/tfpreflight/tfpreflight/rules"

	packdata "github.com/tfpreflight/tfpreflight/packs"
)

// The pack format, defined in the rules package.
const (
	SchemaVersion = rules.SchemaVersion
	ManifestPath  = rules.ManifestPath
)

// Manifest names every file in a pack set and its SHA-256.
type Manifest = rules.Manifest

// Set is a validated pack set.
type Set struct {
	source   string
	id       string
	origin   string
	location string
	files    map[string][]byte
	versions []string
	// ranges are the set's range packs; a per-version file is materialized from
	// one the first time it is read.
	ranges []*rules.RangePack
	mu     sync.Mutex
	cache  map[string][]byte
}

// Versions lists every provider version the set covers, oldest first.
func (s *Set) Versions() []string { return append([]string(nil), s.versions...) }

// Source describes where the set came from.
func (s *Set) Source() string { return s.source }

// ReadFile returns one file of the set, or fs.ErrNotExist, which callers read as
// "no pack for this version". A per-version file, such as
// aws/dependency/rules-6.64.0.json, is materialized from its range pack, and
// exists only for a version the pack covers.
func (s *Set) ReadFile(name string) ([]byte, error) {
	if data, ok := s.files[name]; ok {
		return data, nil
	}
	for _, pack := range s.ranges {
		version, ok := pack.VersionOf(name)
		if !ok || !pack.Covers(version) {
			continue
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if data, ok := s.cache[name]; ok {
			return data, nil
		}
		data, err := pack.Materialize(version)
		if err != nil {
			return nil, err
		}
		s.cache[name] = data
		return data, nil
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

// List returns the names of the set's files directly under dir.
func (s *Set) List(dir string) []string {
	var names []string
	for name := range s.files {
		if path.Dir(name) == dir {
			names = append(names, path.Base(name))
		}
	}
	sort.Strings(names)
	return names
}

// Open reads and validates a pack set.
func Open(fsys fs.FS, source string) (*Set, error) {
	manifest, err := readManifest(fsys, source)
	if err != nil {
		return nil, err
	}
	set := &Set{source: source, files: map[string][]byte{}, cache: map[string][]byte{}, versions: manifest.Versions}
	problems, err := set.loadFiles(fsys, manifest)
	if err != nil {
		return nil, fmt.Errorf("pack set %s: %w", source, err)
	}
	problems = append(problems, set.loadRanges(manifest)...)
	problems = append(problems, set.checkLookups()...)
	if len(set.versions) == 0 {
		problems = append(problems, "the manifest lists no provider versions")
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("pack set %s is invalid:\n  %s", source, strings.Join(problems, "\n  "))
	}
	return set, nil
}

func readManifest(fsys fs.FS, source string) (Manifest, error) {
	data, err := fs.ReadFile(fsys, ManifestPath)
	if err != nil {
		return Manifest{}, fmt.Errorf("pack set %s: read manifest: %w", source, err)
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("pack set %s: parse manifest: %w", source, err)
	}
	if manifest.SchemaVersion != SchemaVersion {
		return Manifest{}, fmt.Errorf("pack set %s: schema version %d, this tfpreflight reads %d", source, manifest.SchemaVersion, SchemaVersion)
	}
	if manifest.Provider != "aws" {
		return Manifest{}, fmt.Errorf("pack set %s: provider %q, want aws", source, manifest.Provider)
	}
	if len(manifest.Files) == 0 {
		return Manifest{}, fmt.Errorf("pack set %s: manifest lists no files", source)
	}
	return manifest, nil
}

// loadFiles reads every file under aws/ whose digest matches the manifest, and
// lists each file that is unlisted, altered or missing.
func (s *Set) loadFiles(fsys fs.FS, manifest Manifest) ([]string, error) {
	seen := map[string]bool{}
	var problems []string
	err := fs.WalkDir(fsys, "aws", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || name == ManifestPath {
			return nil
		}
		want, listed := manifest.Files[name]
		if !listed && osJunk(name) {
			return nil
		}
		seen[name] = true
		if !listed {
			problems = append(problems, name+" is not in the manifest")
			return nil
		}
		content, err := fs.ReadFile(fsys, name)
		if err != nil {
			return err
		}
		if got := Digest(content); got != want {
			problems = append(problems, fmt.Sprintf("%s has SHA-256 %s, manifest says %s", name, got, want))
			return nil
		}
		s.files[name] = content
		return nil
	})
	if err != nil {
		return nil, err
	}
	for name := range manifest.Files {
		if !seen[name] {
			problems = append(problems, name+" is in the manifest but missing")
		}
	}
	return problems, nil
}

// osJunk reports whether a path is a file an operating system or archiver adds
// on its own, such as Finder's .DS_Store and ._ files, __MACOSX, or Windows'
// Thumbs.db: any part starting with "." or "_", which go:embed leaves out of
// the built-in rules too, or a Windows thumbnail or folder settings file. Only
// a file the manifest does not list is ever skipped as junk.
func osJunk(name string) bool {
	for _, part := range strings.Split(name, "/") {
		if strings.HasPrefix(part, ".") || strings.HasPrefix(part, "_") {
			return true
		}
	}
	base := path.Base(name)
	return strings.EqualFold(base, "Thumbs.db") || strings.EqualFold(base, "desktop.ini")
}

// loadRanges reads each range pack and checks it covers exactly the manifest's
// versions.
func (s *Set) loadRanges(manifest Manifest) []string {
	var problems []string
	for name, content := range s.files {
		if !rules.IsRangePack(content) {
			continue
		}
		pack, err := rules.ReadRangePack(content)
		if err == nil {
			err = pack.Validate()
		}
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		if !slices.Equal(pack.Versions, manifest.Versions) {
			problems = append(problems, fmt.Sprintf("%s covers %v, the manifest says %v", name, pack.Versions, manifest.Versions))
		}
		s.ranges = append(s.ranges, pack)
	}
	sort.Slice(s.ranges, func(i, j int) bool { return s.ranges[i].Name < s.ranges[j].Name })
	return problems
}

// checkLookups holds every lookup spec, for every version, to
// rules.Spec.CheckReadOnly: a set that could send AWS anything but a read, or
// send it outside AWS, does not open.
func (s *Set) checkLookups() []string {
	var problems []string
	for _, pack := range s.ranges {
		if !strings.HasPrefix(pack.Name, "aws/lookup/") {
			continue
		}
		if err := pack.CheckSpecs(); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", pack.Name, err))
		}
	}
	for name, content := range s.files {
		if !strings.HasPrefix(name, "aws/lookup/") || rules.IsRangePack(content) {
			continue
		}
		var set rules.SpecSet
		err := json.Unmarshal(content, &set)
		if err == nil {
			err = set.Check()
		}
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", name, err))
		}
	}
	return problems
}

// ValidateMaterialized materializes every covered version of every range pack
// and requires valid JSON. Opening a set checks only structure; a downloaded
// bundle is checked in full before it is installed.
func (s *Set) ValidateMaterialized() error {
	for _, pack := range s.ranges {
		if err := pack.ValidateVersions(); err != nil {
			return err
		}
	}
	return nil
}

// Digest is the manifest's hash of a file.
func Digest(data []byte) string { return rules.Digest(data) }

// Embedded opens the packs built into the binary. They cannot change, so they
// are validated once per process.
var Embedded = sync.OnceValues(func() (*Set, error) {
	set, err := Open(packdata.AWS, "embedded")
	if err != nil {
		return nil, err
	}
	set.id, set.origin = OriginEmbedded, OriginEmbedded
	return set, nil
})

// Dir opens a pack set laid out like packs/: <dir>/aws/...
func Dir(dir string) (*Set, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("pack set %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("pack set %s: not a directory", dir)
	}
	set, err := Open(os.DirFS(dir), dir)
	if err != nil {
		return nil, err
	}
	set.id, set.origin, set.location = OriginDir, OriginDir, dir
	return set, nil
}

var (
	mu     sync.Mutex
	active *Set
)

// Use makes set the one every reader uses. The CLI calls it once, before any
// check runs.
func Use(set *Set) {
	mu.Lock()
	defer mu.Unlock()
	active = set
}

// Active returns the set in use, the built-in packs if none was chosen.
func Active() (*Set, error) {
	mu.Lock()
	defer mu.Unlock()
	if active == nil {
		set, err := Embedded()
		if err != nil {
			return nil, err
		}
		active = set
	}
	return active, nil
}

// ReadFile reads one file of the active set.
func ReadFile(name string) ([]byte, error) {
	set, err := Active()
	if err != nil {
		return nil, err
	}
	return set.ReadFile(name)
}
