// A range pack holds one pack kind for many provider versions. A rule that is
// the same on consecutive versions is stored once, with the versions it holds
// for. Materialize rebuilds one version's pack exactly.

package rules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// RangePackFormat identifies the range pack format.
const RangePackFormat = "tfpreflight-range-pack/1"

// VersionToken replaces, in a stored entry, a "provider_version" member naming
// the pack's own version, so that member does not make otherwise identical rules
// differ between versions.
const VersionToken = "{provider_version}"

// RangePack is one pack kind over many provider versions.
type RangePack struct {
	Format string `json:"format"`
	// Name is the per-version file the pack stands for, with VersionToken for
	// the version: aws/dependency/rules-{provider_version}.json.
	Name string `json:"name"`
	// Versions lists every provider version the pack covers, oldest first.
	Versions []string     `json:"versions"`
	Fields   []RangeField `json:"fields"`
}

// Field kinds: a whole value, an object whose members are entries, or an array
// whose elements are entries.
const (
	FieldValue = "value"
	FieldMap   = "map"
	FieldList  = "list"
)

// RangeField is one top-level member of the per-version pack.
type RangeField struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	// Present is where the member exists at all.
	Present []VersionRange `json:"present"`
	Entries []RangeEntry   `json:"entries"`
	// Order gives, for a version whose list order the entries cannot express,
	// its entries' indexes in order.
	Order map[string][]int `json:"order,omitempty"`
}

// RangeEntry is one value and the versions it holds for.
type RangeEntry struct {
	Versions []VersionRange  `json:"versions"`
	Key      string          `json:"key,omitempty"`
	Value    json.RawMessage `json:"value"`
}

// VersionRange is an inclusive range of the pack's covered versions.
type VersionRange [2]string

// CompareVersions orders provider versions numerically: -1, 0 or 1.
func CompareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// SortVersions sorts provider versions oldest first.
func SortVersions(versions []string) {
	sort.Slice(versions, func(i, j int) bool { return CompareVersions(versions[i], versions[j]) < 0 })
}

// Covers reports whether the pack covers a version.
func (p *RangePack) Covers(version string) bool {
	for _, v := range p.Versions {
		if v == version {
			return true
		}
	}
	return false
}

// FileName is the per-version file name for a version.
func (p *RangePack) FileName(version string) string {
	return strings.Replace(p.Name, VersionToken, version, 1)
}

// VersionOf reports which version a per-version file name stands for.
func (p *RangePack) VersionOf(name string) (string, bool) {
	prefix, suffix, ok := strings.Cut(p.Name, VersionToken)
	if !ok || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) || len(name) <= len(prefix)+len(suffix) {
		return "", false
	}
	return name[len(prefix) : len(name)-len(suffix)], true
}

func inRanges(index map[string]int, ranges []VersionRange, version string) bool {
	at, ok := index[version]
	if !ok {
		return false
	}
	for _, r := range ranges {
		if index[r[0]] <= at && at <= index[r[1]] {
			return true
		}
	}
	return false
}

func (p *RangePack) index() map[string]int {
	index := make(map[string]int, len(p.Versions))
	for i, v := range p.Versions {
		index[v] = i
	}
	return index
}

// Materialize rebuilds one covered version's pack. Object members are sorted, so
// it equals, as JSON, the per-version file the pack was built from.
func (p *RangePack) Materialize(version string) ([]byte, error) {
	if p.Format != RangePackFormat {
		return nil, fmt.Errorf("%s: format %q, this tfpreflight reads %s", p.Name, p.Format, RangePackFormat)
	}
	index := p.index()
	if _, ok := index[version]; !ok {
		return nil, fmt.Errorf("%s does not cover provider %s", p.Name, version)
	}
	var b bytes.Buffer
	b.WriteByte('{')
	first := true
	for _, field := range p.Fields {
		if !inRanges(index, field.Present, version) {
			continue
		}
		if !first {
			b.WriteByte(',')
		}
		first = false
		name, _ := json.Marshal(field.Name)
		b.Write(name)
		b.WriteByte(':')
		if err := p.writeField(&b, index, field, version); err != nil {
			return nil, err
		}
	}
	b.WriteByte('}')
	return untemplate(b.Bytes(), version), nil
}

func (p *RangePack) writeField(b *bytes.Buffer, index map[string]int, field RangeField, version string) error {
	switch field.Kind {
	case FieldValue:
		return p.writeValue(b, index, field, version)
	case FieldMap:
		writeMap(b, index, field, version)
		return nil
	case FieldList:
		return p.writeList(b, index, field, version)
	default:
		return fmt.Errorf("%s: %s has kind %q", p.Name, field.Name, field.Kind)
	}
}

func (p *RangePack) writeValue(b *bytes.Buffer, index map[string]int, field RangeField, version string) error {
	for _, entry := range field.Entries {
		if inRanges(index, entry.Versions, version) {
			b.Write(entry.Value)
			return nil
		}
	}
	return fmt.Errorf("%s: %s has no value for %s", p.Name, field.Name, version)
}

func writeMap(b *bytes.Buffer, index map[string]int, field RangeField, version string) {
	var keys []int
	for i, entry := range field.Entries {
		if inRanges(index, entry.Versions, version) {
			keys = append(keys, i)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return field.Entries[keys[i]].Key < field.Entries[keys[j]].Key })
	b.WriteByte('{')
	for n, i := range keys {
		if n > 0 {
			b.WriteByte(',')
		}
		key, _ := json.Marshal(field.Entries[i].Key)
		b.Write(key)
		b.WriteByte(':')
		b.Write(field.Entries[i].Value)
	}
	b.WriteByte('}')
}

// writeList writes the entries that cover version, in the version's explicit
// order when it has one.
func (p *RangePack) writeList(b *bytes.Buffer, index map[string]int, field RangeField, version string) error {
	order, explicit := field.Order[version]
	if !explicit {
		for i, entry := range field.Entries {
			if inRanges(index, entry.Versions, version) {
				order = append(order, i)
			}
		}
	}
	b.WriteByte('[')
	for n, i := range order {
		if i < 0 || i >= len(field.Entries) {
			return fmt.Errorf("%s: %s orders entry %d of %d", p.Name, field.Name, i, len(field.Entries))
		}
		if n > 0 {
			b.WriteByte(',')
		}
		b.Write(field.Entries[i].Value)
	}
	b.WriteByte(']')
	return nil
}

func versionMember(version string) []byte {
	value, _ := json.Marshal(version)
	return append([]byte(`"provider_version":`), value...)
}

// untemplate puts the version back where the pack stores VersionToken.
func untemplate(data []byte, version string) []byte {
	return bytes.ReplaceAll(data, versionMember(VersionToken), versionMember(version))
}

// ReadRangePack parses a range pack.
func ReadRangePack(data []byte) (*RangePack, error) {
	var pack RangePack
	if err := json.Unmarshal(data, &pack); err != nil {
		return nil, err
	}
	if pack.Format != RangePackFormat {
		return nil, fmt.Errorf("format %q, this tfpreflight reads %s", pack.Format, RangePackFormat)
	}
	return &pack, nil
}

// IsRangePack reports whether a file is a range pack, by its first member.
func IsRangePack(data []byte) bool {
	head := data
	if len(head) > 200 {
		head = head[:200]
	}
	return bytes.Contains(head, []byte(`"format":"`+RangePackFormat+`"`)) || bytes.Contains(head, []byte(`"format": "`+RangePackFormat+`"`))
}

// Encode renders a range pack with one entry per line, so a change to one rule
// is a change to one line.
func (p *RangePack) Encode() ([]byte, error) {
	w := &packWriter{}
	w.b.WriteString("{\n")
	w.line(` "format": `, p.Format, ",\n")
	w.line(` "name": `, p.Name, ",\n")
	w.line(` "versions": `, p.Versions, ",\n")
	w.b.WriteString(" \"fields\": [")
	for f, field := range p.Fields {
		if f > 0 {
			w.b.WriteByte(',')
		}
		w.field(field)
	}
	w.b.WriteString("\n ]\n}\n")
	if w.err != nil {
		return nil, w.err
	}
	return w.b.Bytes(), nil
}

// packWriter writes a range pack's layout and keeps the first marshal error.
type packWriter struct {
	b   bytes.Buffer
	err error
}

func (w *packWriter) line(prefix string, v any, suffix string) {
	if w.err != nil {
		return
	}
	data, err := json.Marshal(v)
	if err != nil {
		w.err = err
		return
	}
	w.b.WriteString(prefix)
	w.b.Write(data)
	w.b.WriteString(suffix)
}

func (w *packWriter) field(field RangeField) {
	w.b.WriteString("\n  {\n")
	w.line(`   "name": `, field.Name, ",\n")
	w.line(`   "kind": `, field.Kind, ",\n")
	w.line(`   "present": `, field.Present, ",\n")
	if field.Order != nil {
		w.line(`   "order": `, field.Order, ",\n")
	}
	w.b.WriteString(`   "entries": [`)
	for e, entry := range field.Entries {
		if e > 0 {
			w.b.WriteByte(',')
		}
		w.line("\n    ", entry, "")
	}
	w.b.WriteString("\n   ]\n  }")
}
