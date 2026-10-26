package packs

import (
	"encoding/json"
	"strings"
	"testing"
	"testing/fstest"
)

func manifestFor(files map[string]string) string {
	m := Manifest{SchemaVersion: SchemaVersion, Provider: "aws", Files: map[string]string{}, Versions: []string{"1.0.0"}}
	for name, content := range files {
		m.Files[name] = Digest([]byte(content))
	}
	data, _ := json.Marshal(m)
	return string(data)
}

func set(files map[string]string, manifest string) fstest.MapFS {
	fsys := fstest.MapFS{ManifestPath: {Data: []byte(manifest)}}
	for name, content := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(content)}
	}
	return fsys
}

func TestOpenValidatesEveryFile(t *testing.T) {
	files := map[string]string{"aws/generated/aws-1.0.0.json": `{"a":1}`, "aws/lookup/specs-1.0.0.json": `{"specs":[]}`}
	good, err := Open(set(files, manifestFor(files)), "test")
	if err != nil {
		t.Fatal(err)
	}
	if data, err := good.ReadFile("aws/lookup/specs-1.0.0.json"); err != nil || string(data) != `{"specs":[]}` {
		t.Fatalf("read = %q, %v", data, err)
	}
	if _, err := good.ReadFile("aws/generated/aws-9.9.9.json"); err == nil {
		t.Fatal("a file the set lacks was read")
	}
	for name, tc := range map[string]struct {
		fsys fstest.MapFS
		want string
	}{
		"tampered":      {set(map[string]string{"aws/generated/aws-1.0.0.json": `{"a":2}`, "aws/lookup/specs-1.0.0.json": `{"specs":[]}`}, manifestFor(files)), "manifest says"},
		"extra file":    {set(map[string]string{"aws/generated/aws-1.0.0.json": `{"a":1}`, "aws/lookup/specs-1.0.0.json": `{"specs":[]}`, "aws/extra.json": `{}`}, manifestFor(files)), "not in the manifest"},
		"missing file":  {set(map[string]string{"aws/generated/aws-1.0.0.json": `{"a":1}`}, manifestFor(files)), "missing"},
		"no manifest":   {fstest.MapFS{"aws/x.json": {Data: []byte("{}")}}, "read manifest"},
		"schema":        {set(files, strings.Replace(manifestFor(files), `"schema_version":2`, `"schema_version":3`, 1)), "schema version 3"},
		"unknown field": {set(files, strings.Replace(manifestFor(files), `{"schema_version"`, `{"signature":"x","schema_version"`, 1)), "unknown field"},
		"empty":         {set(nil, manifestFor(nil)), "no files"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Open(tc.fsys, "test"); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// The shipped packs pass their own manifest.
func TestEmbeddedPacksAreValid(t *testing.T) {
	embedded, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if len(embedded.List("aws/generated")) == 0 || len(embedded.List("aws/lookup")) == 0 {
		t.Fatal("embedded set has no generated or lookup packs")
	}
}
