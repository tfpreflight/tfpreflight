package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Validate checks a range pack's structure without materializing anything, so it
// can run on every load: format and name, versions once each and oldest first,
// field names and kinds, ranges over covered versions in order, a value in every
// entry, and every explicit order indexing an entry. The manifest proves which
// bytes a set holds, not that they form a pack; a broken pack must be refused
// when the set opens, not fail during a check.
func (p *RangePack) Validate() error {
	if p.Format != RangePackFormat {
		return fmt.Errorf("format %q, this tfpreflight reads %s", p.Format, RangePackFormat)
	}
	if !strings.Contains(p.Name, VersionToken) {
		return fmt.Errorf("name %q has no %s", p.Name, VersionToken)
	}
	if err := checkVersions(p.Versions); err != nil {
		return err
	}
	index := p.index()
	names := make(map[string]bool, len(p.Fields))
	for _, field := range p.Fields {
		if field.Name == "" || names[field.Name] {
			return fmt.Errorf("field %q is unnamed or repeated", field.Name)
		}
		names[field.Name] = true
		if err := field.validate(index); err != nil {
			return fmt.Errorf("field %s: %w", field.Name, err)
		}
	}
	return nil
}

// ValidateVersions materializes every covered version and requires one valid
// JSON document each. It reads the whole pack, so it runs when a downloaded
// bundle is installed, not on every load.
func (p *RangePack) ValidateVersions() error {
	if err := p.Validate(); err != nil {
		return err
	}
	for _, version := range p.Versions {
		data, err := p.Materialize(version)
		if err != nil {
			return err
		}
		if !json.Valid(data) {
			return fmt.Errorf("%s does not materialize to valid JSON", p.FileName(version))
		}
	}
	return nil
}

func checkVersions(versions []string) error {
	if len(versions) == 0 {
		return errors.New("covers no versions")
	}
	for i, version := range versions {
		if !isExactVersion(version) {
			return fmt.Errorf("version %q is not an exact version", version)
		}
		if i > 0 && CompareVersions(versions[i-1], version) >= 0 {
			return fmt.Errorf("versions are not strictly oldest first at %s", version)
		}
	}
	return nil
}

func isExactVersion(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return false
		}
	}
	return true
}

func (f RangeField) validate(index map[string]int) error {
	switch f.Kind {
	case FieldValue, FieldMap, FieldList:
	default:
		return fmt.Errorf("kind %q", f.Kind)
	}
	if err := checkRanges(index, f.Present); err != nil {
		return fmt.Errorf("present: %w", err)
	}
	for i, entry := range f.Entries {
		if err := checkRanges(index, entry.Versions); err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
		if len(entry.Value) == 0 {
			return fmt.Errorf("entry %d has no value", i)
		}
	}
	for version, order := range f.Order {
		if _, covered := index[version]; !covered {
			return fmt.Errorf("order for %s, a version the pack does not cover", version)
		}
		for _, i := range order {
			if i < 0 || i >= len(f.Entries) {
				return fmt.Errorf("order for %s names entry %d of %d", version, i, len(f.Entries))
			}
		}
	}
	return nil
}

func checkRanges(index map[string]int, ranges []VersionRange) error {
	for _, r := range ranges {
		first, firstCovered := index[r[0]]
		last, lastCovered := index[r[1]]
		if !firstCovered || !lastCovered {
			return fmt.Errorf("range %s..%s names a version the pack does not cover", r[0], r[1])
		}
		if first > last {
			return fmt.Errorf("range %s..%s runs backwards", r[0], r[1])
		}
	}
	return nil
}
