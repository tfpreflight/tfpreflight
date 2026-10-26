package packs

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tfpreflight/tfpreflight/rules"
)

// Every lookup spec the binary ships, materialized for every covered version,
// passes the read-only gate. A shipped spec that fails it is a pack to fix,
// not a rule to widen.
func TestEveryShippedLookupSpecIsReadOnly(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("materializes every shipped version's lookups")
	}
	embedded, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, version := range embedded.Versions() {
		for _, name := range []string{"aws/lookup/specs-", "aws/lookup/conflict-specs-"} {
			data, err := embedded.ReadFile(name + version + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var set rules.SpecSet
			if err := json.Unmarshal(data, &set); err != nil {
				t.Fatal(err)
			}
			if err := set.Check(); err != nil {
				t.Errorf("%s%s.json: %v", name, version, err)
			}
			checked += len(set.Specs)
		}
	}
	if checked == 0 {
		t.Fatal("no lookup specs were checked")
	}
}

// A pack holding a lookup that is not a read, or that goes outside AWS, does
// not open.
func TestOpenRefusesALookupThatIsNotARead(t *testing.T) {
	t.Parallel()
	read := `{"service":"s3","operation":"HeadBucket","protocol":"restXml","method":"HEAD","path":"/{Bucket}",` +
		`"endpoints":{"standard":{"partitions":{"aws":{"hostname":"s3.{region}.amazonaws.com"}}}}}`
	for name, tc := range map[string]struct{ from, to, want string }{
		"write operation": {`"operation":"HeadBucket"`, `"operation":"DeleteBucket"`, "not a read"},
		"write method":    {`"method":"HEAD"`, `"method":"DELETE"`, "not an allowed read"},
		"POST on REST":    {`"method":"HEAD"`, `"method":"POST"`, "not an allowed read"},
		"foreign host":    {`s3.{region}.amazonaws.com`, `s3.{region}.amazonaws.com.example.net`, "not in an AWS partition"},
		"host lookalike":  {`s3.{region}.amazonaws.com`, `s3.{region}.notamazonaws.com`, "not in an AWS partition"},
		"target header":   {`"path"`, `"headers":{"X-Amz-Target":"DynamoDB_20120810.DeleteTable"},"path"`, "not allowed"},
	} {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{
				"aws/generated/aws-1.0.0.json": `{"a":1}`,
				"aws/lookup/specs-1.0.0.json":  `{"specs":[` + strings.Replace(read, tc.from, tc.to, 1) + `]}`,
			}
			if _, err := Open(set(files, manifestFor(files)), "test"); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
	files := map[string]string{"aws/generated/aws-1.0.0.json": `{"a":1}`, "aws/lookup/specs-1.0.0.json": `{"specs":[` + read + `]}`}
	if _, err := Open(set(files, manifestFor(files)), "test"); err != nil {
		t.Fatalf("a read-only lookup was refused: %v", err)
	}
}
