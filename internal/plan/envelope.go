package plan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ValidateDocument rejects plan JSON that is not one well-formed `terraform show
// -json` document. A malformed plan must fail closed: read permissively, it can
// parse to no changes and look like a clean run. resource_changes and errored
// may be absent, as a plan with no changes or an older Terraform leaves them
// out, but when present must be an array and a boolean.
func ValidateDocument(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var document map[string]json.RawMessage
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("decode plan JSON: %w", err)
	}
	if document == nil {
		return errors.New("plan JSON is null, not an object")
	}
	if err := decoder.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("plan JSON contains a second top-level value")
		}
		return fmt.Errorf("decode plan JSON after its first value: %w", err)
	}
	var version string
	var errored bool
	for _, field := range []planField{
		{name: "format_version", kind: jsonString, required: true, into: &version},
		{name: "errored", kind: jsonBoolean, into: &errored},
		{name: "resource_changes", kind: jsonArray},
		{name: "planned_values", kind: jsonObject, required: true},
	} {
		if err := field.check(document); err != nil {
			return err
		}
	}
	if !strings.HasPrefix(version, "1.") {
		return fmt.Errorf("unsupported format_version %q", version)
	}
	if errored {
		return errors.New("plan contains planning errors")
	}
	return nil
}

// jsonKind is a JSON value's type, named as an error message names it.
type jsonKind string

const (
	jsonString  jsonKind = "a string"
	jsonBoolean jsonKind = "a boolean"
	jsonArray   jsonKind = "an array"
	jsonObject  jsonKind = "an object"
)

type planField struct {
	name     string
	kind     jsonKind
	required bool
	into     any // decoded into when set
}

// check reports a missing required field, or a value of another JSON type, null
// included.
func (f planField) check(document map[string]json.RawMessage) error {
	raw, present := document[f.name]
	if !present {
		if f.required {
			return fmt.Errorf("%s is missing", f.name)
		}
		return nil
	}
	if kindOf(raw) != f.kind {
		return fmt.Errorf("%s must be %s", f.name, f.kind)
	}
	if f.into == nil {
		return nil
	}
	if err := json.Unmarshal(raw, f.into); err != nil {
		return fmt.Errorf("decode %s: %w", f.name, err)
	}
	return nil
}

// kindOf is the type of one well-formed JSON value, or "" for null and numbers,
// which no plan field read here may be.
func kindOf(raw json.RawMessage) jsonKind {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return ""
	}
	switch trimmed[0] {
	case '"':
		return jsonString
	case 't', 'f':
		return jsonBoolean
	case '[':
		return jsonArray
	case '{':
		return jsonObject
	}
	return ""
}
