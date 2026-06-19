// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

// Command omniban is the entrypoint: it sets up a signal-cancelable context and
// hands control to the CLI command tree.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/extremeshok/omniban/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cli.Execute(ctx, version, installSource); err != nil {
		fmt.Fprintln(os.Stderr, "omniban: "+err.Error())
		os.Exit(1)
	}
}
