package plan

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// RegionVariable reports the root input variable the default AWS provider block
// takes its region from, when the region is exactly var.<name>. The plan JSON
// records region = var.region and region = format("%s", var.region) alike, so
// only the source can say the value passes through untouched. ok is false for
// anything else, including a provider block that cannot be found or read.
func RegionVariable(dir string) (name string, ok bool, err error) {
	return ProviderVariable(dir, "", "region")
}

// AssumeRoleVariable is RegionVariable for assume_role's role_arn.
func AssumeRoleVariable(dir string) (name string, ok bool, err error) {
	return ProviderVariable(dir, "assume_role", "role_arn")
}

// ProviderVariable reports the root input variable an attribute of the default
// AWS provider block, or of its nested block when block is set, is exactly, as
// var.<name>.
func ProviderVariable(dir, block, attributeName string) (name string, ok bool, err error) {
	expression, found, err := providerExpression(dir, block, attributeName)
	if err != nil || !found {
		return "", false, err
	}
	return traversalName(expression, "var")
}

// RegionLocal reports the local value the default AWS provider block takes its
// region from, when the region is exactly local.<name> and that local is
// defined once, in this directory, as a plain string. ok is false for anything
// else: a local built from variables, functions or other locals is not read.
func RegionLocal(dir string) (name, value string, ok bool, err error) {
	return ProviderLocal(dir, "", "region")
}

// ProviderLocal is RegionLocal for any string argument of the default AWS
// provider block, or of its nested block when block is set.
func ProviderLocal(dir, block, attributeName string) (name, value string, ok bool, err error) {
	expression, found, err := providerExpression(dir, block, attributeName)
	if err != nil || !found {
		return "", "", false, err
	}
	name, ok, _ = traversalName(expression, "local")
	if !ok {
		return "", "", false, nil
	}
	definitions, err := localDefinitions(dir, name)
	if err != nil || len(definitions) != 1 {
		return name, "", false, err
	}
	value, ok = plainString(definitions[0])
	return name, value, ok, nil
}

// StringListItem is one element of a list the provider block writes out.
type StringListItem struct {
	// Value is a string literal, or a local that is a plain string.
	Value string
	// Var is the root variable the element is exactly, when Value is empty.
	Var string
}

// ProviderStringList reads a list-of-strings argument of the default AWS
// provider block, or of its nested block when block is set, from the source.
// The list may be written out, each element a string literal, exactly
// var.<name> or exactly a local that is a plain string; or be exactly
// var.<name>, a list variable, named by wholeVar; or be exactly a local that is
// a list written out with literals only. ok is false for anything else,
// including a block that cannot be found or read.
func ProviderStringList(dir, block, attributeName string) (items []StringListItem, wholeVar string, ok bool, err error) {
	expression, found, err := providerExpression(dir, block, attributeName)
	if err != nil || !found {
		return nil, "", false, err
	}
	if name, isVariable, _ := traversalName(expression, "var"); isVariable {
		return nil, name, true, nil
	}
	local := func(name string) (string, bool) {
		definitions, err := localDefinitions(dir, name)
		if err != nil || len(definitions) != 1 {
			return "", false
		}
		return plainString(definitions[0])
	}
	if name, isLocal, _ := traversalName(expression, "local"); isLocal {
		definitions, err := localDefinitions(dir, name)
		if err != nil || len(definitions) != 1 {
			return nil, "", false, err
		}
		items, ok = listItems(definitions[0], nil)
		return items, "", ok, nil
	}
	items, ok = listItems(expression, local)
	return items, "", ok, nil
}

// listItems reads a list written out as [a, b]. local resolves an element that
// is a local, and is nil where locals are not allowed.
func listItems(expression hcl.Expression, local func(name string) (string, bool)) ([]StringListItem, bool) {
	list, isList := expression.(*hclsyntax.TupleConsExpr)
	if !isList {
		return nil, false
	}
	items := make([]StringListItem, 0, len(list.Exprs))
	for _, element := range list.Exprs {
		item, ok := listItem(element, local)
		if !ok {
			return nil, false
		}
		items = append(items, item)
	}
	return items, true
}

// listItem reads one element: a string literal, or, where local is set, exactly
// var.<name> or a local that is a plain string.
func listItem(element hcl.Expression, local func(name string) (string, bool)) (StringListItem, bool) {
	if value, isString := plainString(element); isString {
		return StringListItem{Value: value}, true
	}
	if local == nil {
		return StringListItem{}, false
	}
	if name, isVariable, _ := traversalName(element, "var"); isVariable {
		return StringListItem{Var: name}, true
	}
	if name, isLocal, _ := traversalName(element, "local"); isLocal {
		value, found := local(name)
		return StringListItem{Value: value}, found
	}
	return StringListItem{}, false
}

// providerExpression is the one expression the default AWS provider block sets
// for the attribute. found is false when no single expression can be named.
func providerExpression(dir, block, attributeName string) (hcl.Expression, bool, error) {
	paths, err := configurationFiles(dir)
	if err != nil {
		return nil, false, err
	}
	var found []hcl.Expression
	for _, path := range paths {
		expressions, unanswered, err := providerExpressions(path, block, attributeName)
		if err != nil {
			return nil, false, err
		}
		if unanswered {
			return nil, false, nil
		}
		found = append(found, expressions...)
	}
	if len(found) != 1 {
		return nil, false, nil
	}
	return found[0], true, nil
}

func configurationFiles(dir string) ([]string, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.tf"))
	sort.Strings(paths)
	return paths, err
}

// localDefinitions is every expression a locals block in dir gives the local.
func localDefinitions(dir, name string) ([]hcl.Expression, error) {
	paths, err := configurationFiles(dir)
	if err != nil {
		return nil, err
	}
	var definitions []hcl.Expression
	for _, path := range paths {
		body, err := parseBody(path)
		if err != nil {
			return nil, err
		}
		for _, block := range body.Blocks {
			if attribute, set := block.Body.Attributes[name]; block.Type == "locals" && set {
				definitions = append(definitions, attribute.Expr)
			}
		}
	}
	return definitions, nil
}

// plainString is the value of a string literal, such as "eu-west-1". An
// expression that needs a variable, a function or another value is not one.
func plainString(expression hcl.Expression) (string, bool) {
	if len(expression.Variables()) > 0 {
		return "", false
	}
	value, diags := expression.Value(nil)
	if diags.HasErrors() || !value.IsKnown() || value.IsNull() || value.Type() != cty.String || value.AsString() == "" {
		return "", false
	}
	return value.AsString(), true
}

// providerExpressions returns the attribute's expression from each default AWS
// provider block in one file. unanswered is true when a block leaves the
// attribute unset or has other than one nested block: then no single variable
// can be named.
func providerExpressions(path, block, attributeName string) (expressions []hcl.Expression, unanswered bool, err error) {
	// Override files merge into the provider block in ways this reader does not
	// reproduce, so their presence leaves the answer unproven.
	if base := filepath.Base(path); base == "override.tf" || strings.HasSuffix(base, "_override.tf") {
		return nil, false, fmt.Errorf("%s may override the provider block", base)
	}
	body, err := parseBody(path)
	if err != nil {
		return nil, false, err
	}
	for _, provider := range body.Blocks {
		if !isDefaultAWSProvider(provider) {
			continue
		}
		attributes, ok := providerAttributes(provider, block)
		if !ok {
			return nil, true, nil
		}
		attribute, set := attributes[attributeName]
		if !set {
			return nil, true, nil
		}
		expressions = append(expressions, attribute.Expr)
	}
	return expressions, false, nil
}

func parseBody(path string) (*hclsyntax.Body, error) {
	source, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	file, diags := hclsyntax.ParseConfig(source, path, hcl.InitialPos)
	if diags.HasErrors() {
		return nil, fmt.Errorf("parse %s: %s", filepath.Base(path), diags.Error())
	}
	return file.Body.(*hclsyntax.Body), nil
}

func isDefaultAWSProvider(provider *hclsyntax.Block) bool {
	if provider.Type != "provider" || len(provider.Labels) != 1 || provider.Labels[0] != "aws" {
		return false
	}
	_, aliased := provider.Body.Attributes["alias"]
	return !aliased
}

// providerAttributes returns the provider block's attributes, or those of its
// one nested block when block is set.
func providerAttributes(provider *hclsyntax.Block, block string) (hclsyntax.Attributes, bool) {
	if block == "" {
		return provider.Body.Attributes, true
	}
	var nested []*hclsyntax.Block
	for _, b := range provider.Body.Blocks {
		if b.Type == block {
			nested = append(nested, b)
		}
	}
	if len(nested) != 1 {
		return nil, false
	}
	return nested[0].Body.Attributes, true
}

// traversalName is <name> when the expression is exactly <root>.<name>.
func traversalName(expression hcl.Expression, root string) (name string, ok bool, err error) {
	traversal, isTraversal := expression.(*hclsyntax.ScopeTraversalExpr)
	if !isTraversal || len(traversal.Traversal) != 2 || traversal.Traversal.RootName() != root {
		return "", false, nil
	}
	attribute, isAttribute := traversal.Traversal[1].(hcl.TraverseAttr)
	if !isAttribute {
		return "", false, nil
	}
	return attribute.Name, true, nil
}
