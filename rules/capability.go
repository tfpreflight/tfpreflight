package rules

import (
	"bytes"
	"encoding/json"
	"slices"
)

// A rule or lookup spec in a pack may name a capability it needs, in a
// "requires" member. A tfpreflight that does not know the capability leaves the
// entry out when it reads the pack, as if it were not there: no lookup, no
// "unsupported" line, no change to the result. It counts the entries it left out
// so it can say so once.
//
// This is how a pack can gain a kind of check that earlier versions cannot run,
// without cutting those versions off from the rest of the pack. It works for
// versions that know the "requires" member. Versions from before it are kept
// from such packs by the pack schema number instead; see SchemaVersion.

// Capabilities this version understands.
const (
	// CapabilityListingLookups is the list_exact_match lookup, with its fixed
	// and page inputs, and the create semantics duplicate-error-listed. beta.7.
	CapabilityListingLookups = "listing-lookups"
)

// knownCapabilities is every capability this version can run.
var knownCapabilities = []string{CapabilityListingLookups}

// KnowsCapability reports whether this version can run entries that require
// label.
func KnowsCapability(label string) bool { return slices.Contains(knownCapabilities, label) }

// requiredCapability is the capability an entry's JSON value names, or "".
func requiredCapability(value []byte) string {
	if !bytes.Contains(value, []byte(`"requires"`)) {
		return ""
	}
	var entry struct {
		Requires string `json:"requires"`
	}
	if json.Unmarshal(value, &entry) != nil {
		return ""
	}
	return entry.Requires
}

// gate decides which entries a read leaves out.
type gate struct {
	understands func(string) bool
	skipped     int
}

// leavesOut reports whether an entry needs a capability the reader lacks, and
// counts it.
func (g *gate) leavesOut(value []byte) bool {
	if g == nil || g.understands == nil {
		return false
	}
	label := requiredCapability(value)
	if label == "" || g.understands(label) {
		return false
	}
	g.skipped++
	return true
}
