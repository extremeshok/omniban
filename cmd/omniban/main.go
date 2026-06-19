// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

// Command omniban is the entrypoint: it sets up a signal-cancelable context and
// hands control to the CLI command tree.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/extremeshok/omniban/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := cli.Execute(ctx, version, installSource)
	if err == nil {
		return
	}
	// A command may request a specific exit code (e.g. `update --check` returns
	// 10 when an update is available) without an error message.
	var coder interface{ ExitCode() int }
	if errors.As(err, &coder) {
		os.Exit(coder.ExitCode())
	}
	fmt.Fprintln(os.Stderr, "omniban: "+err.Error())
	os.Exit(1)
}
