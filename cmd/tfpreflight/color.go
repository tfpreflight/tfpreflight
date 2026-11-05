package main

import (
	"io"
	"os"
	"runtime"

	"golang.org/x/term"
)

// useColor reports whether the default output should be colored: only when
// out is a terminal, as no-color.org asks, and never when NO_COLOR is set to
// anything or the terminal is "dumb". Windows is left plain, because older
// Windows consoles print the codes as text.
func useColor(out io.Writer) bool {
	file, ok := out.(*os.File)
	if !ok || runtime.GOOS == "windows" {
		return false
	}
	return colorAllowed(term.IsTerminal(int(file.Fd())), os.Getenv)
}

// colorAllowed is the rule behind useColor, with the terminal check and the
// environment passed in.
func colorAllowed(terminal bool, getenv func(string) string) bool {
	return terminal && getenv("NO_COLOR") == "" && getenv("TERM") != "dumb"
}
