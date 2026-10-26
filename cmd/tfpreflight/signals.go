package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/tfpreflight/tfpreflight/internal/plan"
)

// runWithSignals runs the CLI. The first SIGINT or SIGTERM cancels the run,
// which interrupts Terraform gently so it can release a state lock. A second
// one means the user will not wait: Terraform is killed, the temporary plan
// removed, and the process exits 130 at once.
func runWithSignals(c *cobra.Command, args []string, out, diagnostics io.Writer) int {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	var stopping atomic.Bool
	go func() {
		first := <-signals
		cancel(errors.New(first.String() + " signal received"))
		<-signals
		stopping.Store(true)
		_, _ = fmt.Fprintln(diagnostics, "tfpreflight: second signal received; stopping now")
		plan.Abort()
		os.Exit(exitInterrupted)
	}()
	code := runRoot(ctx, c, args, out, diagnostics)
	if stopping.Load() {
		// Killing Terraform ends the run too; the exit is 130, which the
		// goroutine above makes once the temporary plan is removed.
		select {}
	}
	return code
}
