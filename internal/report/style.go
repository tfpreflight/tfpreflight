package report

import "strings"

// The default output uses the terminal's own 16 colors, so a terminal theme
// decides the exact shades.
const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
)

// styler adds color to the default text output. The zero value adds none, so
// reports written to files and pipes stay plain.
type styler struct{ on bool }

func (s styler) wrap(code, text string) string {
	if !s.on || text == "" {
		return text
	}
	return code + text + ansiReset
}

// label colors FAIL red and WARN yellow.
func (s styler) label(label string) string {
	if label == "FAIL" {
		return s.wrap(ansiRed, label)
	}
	return s.wrap(ansiYellow, label)
}

// address makes a resource address bold.
func (s styler) address(address string) string { return s.wrap(ansiBold, address) }

// result colors a result line by its first symbol: ✗ red, ! yellow, ✓ green.
// Lines that start with spaces are the detail under a result and stay plain.
func (s styler) result(line string) string {
	switch {
	case strings.HasPrefix(line, "✗"):
		return s.wrap(ansiRed, line)
	case strings.HasPrefix(line, "!"):
		return s.wrap(ansiYellow, line)
	case strings.HasPrefix(line, "✓"):
		return s.wrap(ansiGreen, line)
	}
	return line
}
