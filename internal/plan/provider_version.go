package plan

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/scanner"
)

// awsProviderSources are the AWS provider's addresses in the Terraform and
// OpenTofu registries; a lock file names one of them.
var awsProviderSources = map[string]bool{
	"registry.terraform.io/hashicorp/aws": true,
	"registry.opentofu.org/hashicorp/aws": true,
}

const openTofuRegistry = "registry.opentofu.org/"

// AWSProviderVersion returns the one exact AWS provider version a lock file
// selects. Duplicate provider blocks and non-literal versions are errors, not
// resolved by first match.
func AWSProviderVersion(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	parser := newLockScanner(data)
	version, blocks := "", 0
	for token := parser.next(); token != scanner.EOF; token = parser.next() {
		if token != scanner.Ident || parser.TokenText() != "provider" {
			continue
		}
		source, err := parser.providerSource()
		if err != nil {
			return "", err
		}
		providerVersion, err := parser.providerVersion(awsProviderSources[source])
		if err != nil {
			return "", err
		}
		if awsProviderSources[source] {
			blocks++
			version = providerVersion
		}
	}
	if parser.err != nil {
		return "", parser.err
	}
	if blocks != 1 || version == "" {
		return "", fmt.Errorf("expected one AWS provider lock entry, found %d", blocks)
	}
	return version, nil
}

// LockNamesOpenTofu reports whether a lock file takes any provider from the
// OpenTofu registry, which only OpenTofu writes.
func LockNamesOpenTofu(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	parser := newLockScanner(data)
	for token := parser.next(); token != scanner.EOF; token = parser.next() {
		if token != scanner.Ident || parser.TokenText() != "provider" {
			continue
		}
		source, err := parser.providerSource()
		if err != nil {
			return false, err
		}
		if strings.HasPrefix(source, openTofuRegistry) {
			return true, nil
		}
		if _, err := parser.providerVersion(false); err != nil {
			return false, err
		}
	}
	return false, parser.err
}

type lockScanner struct {
	scanner.Scanner
	err error
}

func newLockScanner(data []byte) *lockScanner {
	parser := &lockScanner{}
	parser.Init(bytes.NewReader(data))
	parser.Mode = scanner.ScanIdents | scanner.ScanStrings | scanner.ScanComments | scanner.SkipComments
	parser.Error = func(_ *scanner.Scanner, message string) {
		parser.err = fmt.Errorf("invalid provider lock: %s", message)
	}
	return parser
}

func (s *lockScanner) next() rune {
	for {
		token := s.Scan()
		if token != '#' {
			return token
		}
		for s.Peek() != scanner.EOF && s.Peek() != '\n' {
			s.Next()
		}
	}
}

func (s *lockScanner) providerSource() (string, error) {
	if s.next() != scanner.String {
		return "", invalidLock("provider source must be a quoted string")
	}
	source, err := strconv.Unquote(s.TokenText())
	if err != nil {
		return "", fmt.Errorf("decode provider source: %w", err)
	}
	if s.next() != '{' {
		return "", invalidLock("provider block is missing an opening brace")
	}
	return source, nil
}

func (s *lockScanner) providerVersion(aws bool) (string, error) {
	depth, versionFields, version := 1, 0, ""
	for depth > 0 {
		token := s.next()
		if token == scanner.EOF {
			return "", invalidLock("provider block is not terminated")
		}
		switch token {
		case '{':
			depth++
		case '}':
			depth--
		}
		if !aws || depth != 1 || token != scanner.Ident || s.TokenText() != "version" {
			continue
		}
		versionFields++
		if s.next() != '=' || s.next() != scanner.String {
			return "", invalidLock("AWS provider version must be a literal string")
		}
		decoded, err := strconv.Unquote(s.TokenText())
		if err != nil {
			return "", fmt.Errorf("decode AWS provider version: %w", err)
		}
		version = decoded
	}
	if aws && versionFields != 1 {
		return "", fmt.Errorf("expected one AWS version attribute, found %d", versionFields)
	}
	return version, nil
}

func invalidLock(message string) error { return fmt.Errorf("invalid provider lock: %s", message) }
