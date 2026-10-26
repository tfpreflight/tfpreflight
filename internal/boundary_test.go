// Package internal_test checks that shipped code depends only on what the
// runtime module declares: the standard library, this module, and the
// modules its go.mod requires. Nothing else can reach a user's machine.
package internal_test

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
)

const module = "github.com/tfpreflight/tfpreflight"

const repoRoot = ".."

// shipped are the trees of the runtime module.
var shipped = []string{"internal", "cmd", "rules", "packs"}

// requiredModules are the module paths go.mod requires.
func requiredModules(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := modfile.ParseLax("go.mod", data, nil)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, require := range file.Require {
		paths = append(paths, require.Mod.Path)
	}
	return paths
}

// declared reports whether importPath is in the standard library, this
// module, or a module go.mod requires.
func declared(importPath string, modules []string) bool {
	first, _, _ := strings.Cut(importPath, "/")
	if !strings.Contains(first, ".") {
		return true
	}
	for _, prefix := range append([]string{module}, modules...) {
		if importPath == prefix || strings.HasPrefix(importPath, prefix+"/") {
			return true
		}
	}
	return false
}

func TestDeclaredAcceptsOnlyDeclaredModules(t *testing.T) {
	modules := []string{"github.com/spf13/cobra"}
	for path, want := range map[string]bool{
		"os/exec":                                  true,
		module + "/internal/checks/quotas":         true,
		"github.com/spf13/cobra/doc":               true,
		"github.com/spf13/cobra-extra":             false,
		"github.com/tfpreflight/tfpreflight-other": false,
		"example.com/anything":                     false,
	} {
		if got := declared(path, modules); got != want {
			t.Errorf("declared(%q) = %v, want %v", path, got, want)
		}
	}
}

// Every file is checked, test files included, so no test can pull in code
// the module does not declare.
func TestShippedCodeImportsOnlyDeclaredModules(t *testing.T) {
	modules := requiredModules(t)
	files := 0
	for _, tree := range shipped {
		root := filepath.Join(repoRoot, tree)
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if entry.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if filepath.Ext(path) != ".go" {
				return nil
			}
			files++
			imports, err := undeclaredImports(path, modules)
			for _, importPath := range imports {
				rel, _ := filepath.Rel(repoRoot, path)
				t.Errorf("%s imports %s, which go.mod does not declare", rel, importPath)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if files == 0 {
		t.Fatal("no Go files found under the shipped trees; the test is not looking in the right place")
	}
}

// undeclaredImports lists the imports of one Go file that are not declared.
func undeclaredImports(path string, modules []string) ([]string, error) {
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	var imports []string
	for _, spec := range parsed.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return imports, err
		}
		if !declared(importPath, modules) {
			imports = append(imports, importPath)
		}
	}
	return imports, nil
}

// The build graph also catches a dependency reached through another package.
// It is computed with GOWORK=off, so the module must build from its own go.mod.
func TestBuildGraphHasOnlyDeclaredModules(t *testing.T) {
	if testing.Short() {
		t.Skip("go list walks the build graph")
	}
	modules := requiredModules(t)
	args := []string{"list", "-deps", "-test", "-json=ImportPath"}
	for _, tree := range shipped {
		args = append(args, "./"+tree+"/...")
	}
	command := exec.Command("go", args...)
	command.Dir = repoRoot
	command.Env = append(os.Environ(), "GOWORK=off")
	output, err := command.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	packages := 0
	for decoder.More() {
		var pkg struct{ ImportPath string }
		if err := decoder.Decode(&pkg); err != nil {
			t.Fatal(err)
		}
		packages++
		// go list -test names test variants "pkg [pkg.test]"; the import path
		// is the part before the bracket.
		importPath, _, _ := strings.Cut(pkg.ImportPath, " ")
		if !declared(importPath, modules) {
			t.Errorf("%s is in the build graph, but go.mod does not declare it", importPath)
		}
	}
	if packages == 0 {
		t.Fatal("go list returned no packages")
	}
}
