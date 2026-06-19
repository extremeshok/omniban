// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

// Package cli builds omniban's cobra command tree and shared application state.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/extremeshok/omniban/internal/config"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/logging"
	"github.com/extremeshok/omniban/internal/manager"
)

// app holds shared state and parsed global flags for the command tree.
type app struct {
	cfg     config.Config
	runner  exec.Runner
	mgr     *manager.Manager
	out     io.Writer
	version string

	flagConfig   string
	flagJSON     bool
	flagDryRun   bool
	flagNoColor  bool
	flagYes      bool
	flagForce    bool
	flagLogLevel string
}

// Execute builds and runs the root command bound to ctx. version is the
// stamped build version.
func Execute(ctx context.Context, version string) error {
	a := &app{out: os.Stdout, runner: exec.New(), version: version}
	return a.rootCmd().ExecuteContext(ctx)
}

func (a *app) rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "omniban",
		Short:         "One ban manager for every Linux firewall & IDS",
		Long:          "omniban — view, search, and manage IP bans, domain sinkholes, and null-routes\nacross every firewall and intrusion-defense tool on a Linux server.",
		Version:       a.version,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// No subcommand: a full-screen TUI lands in M5. For now, show help.
			if isInteractive() {
				fmt.Fprintln(a.out, "omniban: the interactive TUI arrives in a later milestone — showing help for now.")
			}
			return cmd.Help()
		},
		PersistentPreRunE: a.preRun,
	}

	pf := root.PersistentFlags()
	pf.StringVar(&a.flagConfig, "config", config.DefaultConfigPath, "config file path")
	pf.BoolVar(&a.flagJSON, "json", false, "machine-readable JSON output")
	pf.BoolVar(&a.flagDryRun, "dry-run", false, "preview actions without executing them")
	pf.BoolVar(&a.flagNoColor, "no-color", false, "disable colored output")
	pf.BoolVarP(&a.flagYes, "yes", "y", false, "skip confirmation prompts")
	pf.BoolVar(&a.flagForce, "force", false, "override the lockout-prevention guard")
	pf.StringVar(&a.flagLogLevel, "log-level", "", "log level: debug|info|warn|error")

	root.AddCommand(
		a.statusCmd(),
		a.doctorCmd(),
		a.versionCmd(),
		a.initCmd(),
	)
	return root
}

// preRun loads configuration and constructs the manager before any subcommand.
func (a *app) preRun(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load(a.flagConfig)
	if err != nil {
		return err
	}
	if a.flagLogLevel != "" {
		cfg.LogLevel = a.flagLogLevel
	}
	a.cfg = cfg
	// Diagnostic logger to stderr; the audit trail is separate (added in M2).
	_ = logging.Setup(os.Stderr, cfg.LogLevel, a.flagJSON)
	a.mgr = manager.New(cfg, a.runner)
	return nil
}

// requireRoot returns an error unless the process is running as root. Most
// backends need root to query or mutate; commands that read public files only
// (e.g. version) skip this.
func requireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("omniban must run as root (try: sudo omniban …)")
	}
	return nil
}

// isInteractive reports whether stdin is a terminal.
func isInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
