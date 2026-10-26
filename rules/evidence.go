package rules

// EvidenceSummary is what a rule's verification record observed, when, and which
// record it is with its SHA-256, so a pack can be checked without the records
// themselves.
type EvidenceSummary struct {
	// Observed is what the record shows, in one line.
	Observed string `json:"observed"`
	// ObservedAt is when: the record's own time, or else the date the record was
	// first committed, which is no earlier than the observation.
	// ObservedAtSource says which ("record" or "first_committed").
	ObservedAt       string `json:"observed_at"`
	ObservedAtSource string `json:"observed_at_source"`
	// Record is the record's path, and SHA256 the hex SHA-256 of its bytes.
	Record string `json:"record,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	// NoRecord, set instead of Record, says why the rule has no record.
	NoRecord string `json:"no_record,omitempty"`
	// ObservedOn lists the provider versions the evidence was observed on. It
	// applies to any version whose fingerprint, the hash of the facts it proves,
	// is the same.
	ObservedOn  []string `json:"observed_on,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
}
