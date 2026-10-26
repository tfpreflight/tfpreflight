package main

import "os"

func main() {
	os.Exit(runWithSignals(newRootCommand(), os.Args[1:], os.Stdout, os.Stderr))
}
