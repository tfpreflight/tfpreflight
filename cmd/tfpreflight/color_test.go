package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestColorAllowed(t *testing.T) {
	env := func(values map[string]string) func(string) string {
		return func(key string) string { return values[key] }
	}
	for name, tc := range map[string]struct {
		terminal bool
		env      map[string]string
		want     bool
	}{
		"terminal":              {true, nil, true},
		"pipe or file":          {false, nil, false},
		"NO_COLOR set":          {true, map[string]string{"NO_COLOR": "1"}, false},
		"dumb terminal":         {true, map[string]string{"TERM": "dumb"}, false},
		"xterm":                 {true, map[string]string{"TERM": "xterm-256color"}, true},
		"empty NO_COLOR is off": {true, map[string]string{"NO_COLOR": ""}, true},
	} {
		if got := colorAllowed(tc.terminal, env(tc.env)); got != tc.want {
			t.Errorf("%s: colorAllowed = %v, want %v", name, got, tc.want)
		}
	}
}

func TestUseColorIsOffForBuffersAndFiles(t *testing.T) {
	if useColor(&bytes.Buffer{}) {
		t.Error("a buffer must not be colored")
	}
	file, err := os.Create(filepath.Join(t.TempDir(), "out.txt"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	if useColor(file) {
		t.Error("a regular file must not be colored")
	}
}

// /dev/null is a character device but not a terminal.
func TestUseColorIsOffForDevNull(t *testing.T) {
	file, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	if useColor(file) {
		t.Error("/dev/null must not be colored")
	}
}
