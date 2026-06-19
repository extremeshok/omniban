// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

const sampleConfig = `# omniban configuration — https://github.com/extremeshok/omniban

# Which firewall backend receives manual inbound bans when several are active.
# One of: csf, firewalld, ufw, nftables, iptables. Empty = auto-select by priority.
manual_ban_backend: ""

# Audit-trail log file (JSON lines).
log_file: /var/log/omniban.log

# Directory for the undo journal and persisted blackhole routes.
state_dir: /var/lib/omniban

# TUI auto-refresh interval in seconds (0 = manual refresh only).
refresh_seconds: 0

# Diagnostic log level: debug | info | warn | error
log_level: info

# Always-protected IPs/CIDRs for lockout prevention (added to your SSH client IP).
admin_allowlist: []

# Backends to ignore even when detected (by name).
disabled_backends: []
`

func (a *app) initCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Write a default configuration file",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			path := a.flagConfig
			if _, err := os.Stat(path); err == nil && !a.flagForce {
				return fmt.Errorf("config %s already exists (use --force to overwrite)", path)
			}
			if a.flagDryRun {
				fmt.Fprintf(a.out, "[dry-run] would write default config to %s\n", path)
				return nil
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return fmt.Errorf("create config dir: %w", err)
			}
			if err := os.WriteFile(path, []byte(sampleConfig), 0o644); err != nil {
				return fmt.Errorf("write config: %w", err)
			}
			fmt.Fprintf(a.out, "wrote default config to %s\n", path)
			return nil
		},
	}
}
