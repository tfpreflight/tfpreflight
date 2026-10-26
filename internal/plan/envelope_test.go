package plan

import (
	"strings"
	"testing"
)

// A malformed plan fails closed, and the error names the field. A plan
// without resource_changes is valid: Terraform omits the key when nothing
// changes. A plan without errored is valid too: older Terraform omits it.
func TestValidatePlanDocumentRejectsMalformedFields(t *testing.T) {
	const valid = `{"format_version":"1.2","errored":false,"resource_changes":[],"planned_values":{}}`
	for _, test := range []struct {
		name string
		plan string
		want string // "" when the plan is valid
	}{
		{name: "valid", plan: valid},
		{name: "no resource changes", plan: `{"format_version":"1.2","errored":false,"planned_values":{}}`},
		{name: "format version number", plan: `{"format_version":1.2,"errored":false,"resource_changes":[],"planned_values":{}}`, want: "format_version must be a string"},
		{name: "format version null", plan: `{"format_version":null,"errored":false,"resource_changes":[],"planned_values":{}}`, want: "format_version must be a string"},
		{name: "format version unsupported", plan: `{"format_version":"2.0","errored":false,"resource_changes":[],"planned_values":{}}`, want: `unsupported format_version "2.0"`},
		{name: "errored string", plan: `{"format_version":"1.2","errored":"false","resource_changes":[],"planned_values":{}}`, want: "errored must be a boolean"},
		{name: "errored string true", plan: `{"format_version":"1.2","errored":"true","resource_changes":[],"planned_values":{}}`, want: "errored must be a boolean"},
		{name: "errored false", plan: `{"format_version":"1.2","errored":false,"resource_changes":[],"planned_values":{}}`},
		{name: "errored null", plan: `{"format_version":"1.2","errored":null,"resource_changes":[],"planned_values":{}}`, want: "errored must be a boolean"},
		{name: "errored true", plan: `{"format_version":"1.2","errored":true,"resource_changes":[],"planned_values":{}}`, want: "plan contains planning errors"},
		{name: "resource changes object", plan: `{"format_version":"1.2","errored":false,"resource_changes":{},"planned_values":{}}`, want: "resource_changes must be an array"},
		{name: "resource changes null", plan: `{"format_version":"1.2","errored":false,"resource_changes":null,"planned_values":{}}`, want: "resource_changes must be an array"},
		{name: "planned values array", plan: `{"format_version":"1.2","errored":false,"resource_changes":[],"planned_values":[]}`, want: "planned_values must be an object"},
		{name: "planned values null", plan: `{"format_version":"1.2","errored":false,"resource_changes":[],"planned_values":null}`, want: "planned_values must be an object"},
		{name: "missing format version", plan: `{"errored":false,"resource_changes":[],"planned_values":{}}`, want: "format_version is missing"},
		{name: "missing errored", plan: `{"format_version":"1.2","resource_changes":[],"planned_values":{}}`},
		{name: "missing planned values", plan: `{"format_version":"1.2","errored":false,"resource_changes":[]}`, want: "planned_values is missing"},
		{name: "second value", plan: valid + `{}`, want: "plan JSON contains a second top-level value"},
		{name: "trailing garbage", plan: valid + ` x`, want: "decode plan JSON after its first value"},
		{name: "top level null", plan: `null`, want: "plan JSON is null, not an object"},
		{name: "top level array", plan: `[]`, want: "decode plan JSON"},
		{name: "not JSON", plan: `not JSON`, want: "decode plan JSON"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateDocument([]byte(test.plan))
			if test.want == "" {
				if err != nil {
					t.Fatalf("valid plan rejected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want text %q", err, test.want)
			}
		})
	}
}
