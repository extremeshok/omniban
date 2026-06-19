// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/extremeshok/omniban/internal/selfupdate"
)

const (
	updateServicePath = "/etc/systemd/system/omniban-update.service"
	updateTimerPath   = "/etc/systemd/system/omniban-update.timer"
	updateTimerUnit   = "omniban-update.timer"
	updateCheckTTL    = 24 * time.Hour
)

// packageUpdateMsg is printed when self-update is invoked on a package-managed
// build, pointing the operator at the owning package manager instead.
const packageUpdateMsg = `omniban was installed via your distribution package; update it with the package manager:
  apt-get update && apt-get install --only-upgrade omniban   # Debian / Ubuntu
  dnf upgrade omniban                                         # RHEL / AlmaLinux / Rocky
`

// updateService is the systemd oneshot template; %s is the absolute binary path.
const updateService = `[Unit]
Description=omniban self-update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=%s update --yes
`

const updateTimer = `[Unit]
Description=omniban daily self-update

[Timer]
OnCalendar=daily
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
`

// updateAvailableError makes `update --check` exit 10 when a newer release
// exists, mirroring pi-optimiser's --check-update convention. main maps any
// error exposing ExitCode() to that code without printing a message.
type updateAvailableError struct{}

func (updateAvailableError) Error() string { return "update available" }
func (updateAvailableError) ExitCode() int { return 10 }

func (a *app) updateCmd() *cobra.Command {
	var checkOnly, enableTimer, disableTimer bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update omniban to the latest release (standalone installs only)",
		Long: "Update omniban to the latest GitHub release. The download is verified\n" +
			"against the release checksums (SHA-256) before the running binary is\n" +
			"atomically replaced; the previous binary is kept at <path>.bak.\n\n" +
			"Self-update is disabled for .deb/.rpm installs — those defer to apt/dnf.\n" +
			"Use --enable-timer to install a systemd timer for hands-off daily updates.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			switch {
			case enableTimer:
				return a.enableUpdateTimer(cmd.Context())
			case disableTimer:
				return a.disableUpdateTimer(cmd.Context())
			default:
				return a.runUpdate(cmd.Context(), checkOnly)
			}
		},
	}
	f := cmd.Flags()
	f.BoolVar(&checkOnly, "check", false, "only report whether an update is available")
	f.BoolVar(&enableTimer, "enable-timer", false, "install + enable a systemd timer for automatic daily updates")
	f.BoolVar(&disableTimer, "disable-timer", false, "stop + remove the automatic-update systemd timer")
	return cmd
}

// runUpdate checks for and (unless checkOnly) applies the latest release.
func (a *app) runUpdate(ctx context.Context, checkOnly bool) error {
	managed := a.isPackageManaged(ctx)

	// A plain apply on a package-managed build needs no network round-trip.
	if managed && !checkOnly && !a.flagJSON {
		fmt.Fprint(a.out, packageUpdateMsg)
		return nil
	}

	st, err := selfupdate.Check(ctx, nil, a.version)
	if err != nil {
		return err
	}

	if a.flagJSON {
		enc := json.NewEncoder(a.out)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Current         string `json:"current"`
			Latest          string `json:"latest"`
			UpdateAvailable bool   `json:"update_available"`
			PackageManaged  bool   `json:"package_managed"`
		}{st.Current, st.Latest, st.Available && !managed, managed})
	}

	if checkOnly {
		a.printUpdateStatus(st, managed)
		if st.Available {
			// Exit 10 when a newer release exists (mirrors pi-optimiser's
			// --check-update) so `if ! omniban update --check; then ...` works.
			return updateAvailableError{}
		}
		return nil
	}
	if managed {
		fmt.Fprint(a.out, packageUpdateMsg)
		return nil
	}
	if !st.Available {
		fmt.Fprintf(a.out, "omniban %s is already up to date\n", a.version)
		return nil
	}

	if err := requireRoot(); err != nil {
		return err
	}
	exe, err := resolveExe()
	if err != nil {
		return err
	}

	if a.flagDryRun {
		asset := st.AssetName()
		if asset == "" {
			asset = "(no matching release asset for this OS/arch)"
		}
		fmt.Fprintf(a.out, "[dry-run] would update omniban %s -> %s\n", st.Current, st.Latest)
		fmt.Fprintf(a.out, "    download: %s\n", asset)
		fmt.Fprintf(a.out, "    verify:   checksums.txt (sha256)\n")
		fmt.Fprintf(a.out, "    replace:  %s (backup: %s.bak)\n", exe, exe)
		return nil
	}

	if !a.flagYes && !confirmPrompt(a.out, fmt.Sprintf("Update omniban %s -> %s?", st.Current, st.Latest)) {
		fmt.Fprintln(a.out, "cancelled")
		return nil
	}
	if err := selfupdate.Apply(ctx, nil, st, exe); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "updated omniban %s -> %s (previous binary kept at %s.bak)\n", st.Current, st.Latest, exe)
	return nil
}

func (a *app) printUpdateStatus(st selfupdate.Status, managed bool) {
	fmt.Fprintf(a.out, "current: %s\n", st.Current)
	fmt.Fprintf(a.out, "latest:  %s\n", st.Latest)
	switch {
	case managed:
		fmt.Fprintln(a.out, "status:  managed by the distribution package manager (apt/dnf)")
	case st.Available:
		fmt.Fprintln(a.out, "status:  update available — run: sudo omniban update")
	default:
		fmt.Fprintln(a.out, "status:  up to date")
	}
}

// isPackageManaged reports whether updates must defer to a distro package
// manager: either the build is stamped installSource=package, or the running
// executable is owned by dpkg/rpm (a runtime backstop for source builds dropped
// into a package-owned path).
func (a *app) isPackageManaged(ctx context.Context) bool {
	if selfupdate.Managed(a.installSource) {
		return true
	}
	exe, err := resolveExe()
	if err != nil {
		return false
	}
	if _, err := a.runner.Run(ctx, "dpkg", "-S", exe); err == nil {
		return true
	}
	if _, err := a.runner.Run(ctx, "rpm", "-qf", exe); err == nil {
		return true
	}
	return false
}

func (a *app) enableUpdateTimer(ctx context.Context) error {
	if selfupdate.Managed(a.installSource) {
		return fmt.Errorf("this build is managed by your distribution package manager; use it to update rather than an omniban timer")
	}
	if err := requireRoot(); err != nil {
		return err
	}
	exe, err := resolveExe()
	if err != nil {
		return err
	}
	if a.flagDryRun {
		fmt.Fprintf(a.out, "[dry-run] would write %s and %s, then: systemctl daemon-reload; systemctl enable --now %s\n",
			updateServicePath, updateTimerPath, updateTimerUnit)
		return nil
	}
	if err := os.WriteFile(updateServicePath, []byte(fmt.Sprintf(updateService, exe)), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", updateServicePath, err)
	}
	if err := os.WriteFile(updateTimerPath, []byte(updateTimer), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", updateTimerPath, err)
	}
	if _, err := a.runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if _, err := a.runner.Run(ctx, "systemctl", "enable", "--now", updateTimerUnit); err != nil {
		return fmt.Errorf("enable %s: %w", updateTimerUnit, err)
	}
	fmt.Fprintf(a.out, "enabled automatic daily updates (%s)\n", updateTimerUnit)
	return nil
}

func (a *app) disableUpdateTimer(ctx context.Context) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if a.flagDryRun {
		fmt.Fprintf(a.out, "[dry-run] would: systemctl disable --now %s; remove %s and %s; systemctl daemon-reload\n",
			updateTimerUnit, updateTimerPath, updateServicePath)
		return nil
	}
	// Best-effort: the timer may not be installed.
	_, _ = a.runner.Run(ctx, "systemctl", "disable", "--now", updateTimerUnit)
	_ = os.Remove(updateTimerPath)
	_ = os.Remove(updateServicePath)
	_, _ = a.runner.Run(ctx, "systemctl", "daemon-reload")
	fmt.Fprintln(a.out, "disabled automatic updates")
	return nil
}

// --- passive update notifier -----------------------------------------------

type updateCache struct {
	LastCheckUnix int64  `json:"last_check_unix"`
	Latest        string `json:"latest"`
}

// maybeNotifyUpdate prints a one-line "newer version available" notice to stderr
// on interactive, standalone-binary runs. It is throttled by a cache in StateDir
// so at most one network check happens per updateCheckTTL, and every step is
// best-effort: any error (offline, unwritable cache) is swallowed silently.
func (a *app) maybeNotifyUpdate(ctx context.Context) {
	if a.flagJSON || !a.cfg.UpdateCheck {
		return
	}
	if selfupdate.Managed(a.installSource) || os.Getenv("OMNIBAN_NO_UPDATE_CHECK") != "" {
		return
	}
	if !isInteractive() {
		return
	}
	latest := a.cachedOrFreshLatest(ctx)
	if latest == "" || !selfupdate.Newer(latest, a.version) {
		return
	}
	fmt.Fprintf(os.Stderr, "omniban %s is available (current %s) — run: sudo omniban update\n", latest, a.version)
}

func (a *app) cachedOrFreshLatest(ctx context.Context) string {
	c := a.loadUpdateCache()
	if c.Latest != "" && time.Since(time.Unix(c.LastCheckUnix, 0)) < updateCheckTTL {
		return c.Latest
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	st, err := selfupdate.Check(cctx, &http.Client{Timeout: 3 * time.Second}, a.version)
	if err != nil {
		return c.Latest // fall back to any stale value, silently
	}
	a.saveUpdateCache(updateCache{LastCheckUnix: time.Now().Unix(), Latest: st.Latest})
	return st.Latest
}

func (a *app) updateCachePath() string {
	return filepath.Join(a.cfg.StateDir, "update-check.json")
}

func (a *app) loadUpdateCache() updateCache {
	var c updateCache
	b, err := os.ReadFile(a.updateCachePath())
	if err != nil {
		return c
	}
	_ = json.Unmarshal(b, &c)
	return c
}

func (a *app) saveUpdateCache(c updateCache) {
	if err := os.MkdirAll(a.cfg.StateDir, 0o755); err != nil {
		return
	}
	if b, err := json.Marshal(c); err == nil {
		_ = os.WriteFile(a.updateCachePath(), b, 0o644)
	}
}

// --- helpers ---------------------------------------------------------------

func resolveExe() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return exe, nil
}

func confirmPrompt(out io.Writer, question string) bool {
	fmt.Fprintf(out, "%s [y/N]: ", question)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}
