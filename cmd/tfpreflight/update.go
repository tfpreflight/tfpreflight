package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/tfpreflight/tfpreflight/internal/packs"
)

// updateTimeout bounds an update, so a slow network costs a check no more than
// this.
const updateTimeout = 2 * time.Minute

func updateCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "update",
		Short: "Download the newest signed rules into the user cache",
		Long: `Download the newest rules bundle the rules index lists, check its signature
and every hash, and keep it in the user cache with the previous one as a
fallback. The index is --index, else ` + packs.IndexEnv + `.

Exit 0: the newest rules are in the cache, downloaded now or already there.
Exit 2: they are not; the index or bundle could not be fetched (unreachable, an
HTTP error, a missing file) or failed its checks, and the rules in use are
unchanged. check --update instead warns and carries on with the rules in use.`,
		Example: `  tfpreflight update
  tfpreflight update --index=https://packs.example.com/index.json`,
		Args: cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if err := runUpdate(command.Context(), command.OutOrStdout(), indexLocation(command), ""); err != nil {
				return toolFailure(fmt.Errorf("rules not updated; the rules in use are unchanged: %w", err))
			}
			return nil
		},
	}
	command.Flags().String("index", "", "rules index URL or path (default: "+packs.IndexEnv+")")
	return command
}

func indexLocation(command *cobra.Command) string {
	if index, err := command.Flags().GetString("index"); err == nil && index != "" {
		return index
	}
	if index := os.Getenv(packs.IndexEnv); index != "" {
		return index
	}
	return packs.DefaultIndex
}

// runUpdate updates the cached rules and reports what happened, each line led by
// prefix. It returns why the newest rules are not in the cache.
func runUpdate(ctx context.Context, out io.Writer, index, prefix string) error {
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()
	update, err := packs.Update(ctx, &http.Client{Timeout: updateTimeout}, index)
	for _, id := range update.Skipped {
		_, _ = fmt.Fprintf(out, "%srules bundle %s needs a newer tfpreflight; update tfpreflight to use it\n", prefix, id)
	}
	var network *packs.NetworkError
	switch {
	case errors.As(err, &network):
		return fmt.Errorf("could not fetch the rules (%w)", network.Err)
	case err != nil:
		return err
	case update.Fresh:
		_, _ = fmt.Fprintf(out, "%srules updated to %s, covering AWS provider %s to %s (%d versions)\n", prefix, update.ID, update.Versions[0], update.Versions[len(update.Versions)-1], len(update.Versions))
	default:
		_, _ = fmt.Fprintf(out, "%srules %s are the newest; nothing to download\n", prefix, update.ID)
	}
	return nil
}
