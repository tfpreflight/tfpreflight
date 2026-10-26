package main

import (
	"errors"

	"github.com/tfpreflight/tfpreflight/internal/report"
)

const (
	exitSuccess     = 0
	exitBlocking    = 1
	exitToolFailure = 2
	// exitInterrupted is the shell's code for a process stopped by SIGINT.
	exitInterrupted = 130
)

type checkOutcome struct {
	Report    report.Report
	ToolError error
}

func (o checkOutcome) commandError() error {
	if o.ToolError != nil {
		return &exitError{code: exitToolFailure, err: o.ToolError}
	}
	if reason, _ := o.Report.Failure(); reason != "" {
		return &exitError{code: exitBlocking, err: errors.New(reason)}
	}
	return nil
}

type exitError struct {
	code int
	err  error
}

// Error returns the command failure message.
func (e *exitError) Error() string { return e.err.Error() }

// Unwrap returns the underlying command failure.
func (e *exitError) Unwrap() error { return e.err }

func exitCode(err error) int {
	if err == nil {
		return exitSuccess
	}
	var status *exitError
	if errors.As(err, &status) {
		return status.code
	}
	return exitToolFailure
}

func toolFailure(err error) error {
	return &exitError{code: exitToolFailure, err: err}
}
