// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package denyhosts

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/extremeshok/omniban/internal/model"
)

// servicePrefix is the daemon prefix DenyHosts writes before each blocked host
// in /etc/hosts.deny ("sshd: 1.2.3.4").
const servicePrefix = "sshd"

// ListBans reads /etc/hosts.deny and reports each blocked host. Lines look like
// "sshd: 1.2.3.4"; the value is whatever follows the last colon.
func (b *Backend) ListBans(_ context.Context) ([]model.Entry, error) {
	lines, err := readLines(b.hostsDeny)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", b.hostsDeny, err)
	}
	out := make([]model.Entry, 0, len(lines))
	for _, line := range lines {
		raw := line
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		value := line
		if i := strings.LastIndex(line, ":"); i >= 0 {
			value = strings.TrimSpace(line[i+1:])
		}
		if value == "" {
			continue
		}
		out = append(out, model.Entry{
			Value:     value,
			Family:    familyOf(value),
			Scope:     scopeOf(value),
			Kind:      model.KindBan,
			Direction: model.DirInbound,
			Origin:    model.OriginDenyHosts,
			Backend:   string(model.OriginDenyHosts),
			Raw:       strings.TrimRight(raw, "\n"),
		})
	}
	return out, nil
}

// ListAllows reads the DenyHosts allowed-hosts file (one IP/CIDR per line).
func (b *Backend) ListAllows(_ context.Context) ([]model.Entry, error) {
	lines, err := readLines(b.allowedHosts)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", b.allowedHosts, err)
	}
	out := make([]model.Entry, 0, len(lines))
	for _, line := range lines {
		value := strings.TrimSpace(line)
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		out = append(out, model.Entry{
			Value:     value,
			Family:    familyOf(value),
			Scope:     scopeOf(value),
			Kind:      model.KindAllow,
			Direction: model.DirInbound,
			Origin:    model.OriginDenyHosts,
			Backend:   string(model.OriginDenyHosts),
			Raw:       value,
		})
	}
	return out, nil
}

// Ban coordinates a DenyHosts block: stop the daemon, append "sshd: <ip>" to
// hosts.deny and "<ip>" to the work files, then restart. DenyHosts owns no
// management API, so omniban performs the whole sequence itself.
func (b *Backend) Ban(ctx context.Context, req model.ActionRequest) (model.Result, error) {
	if familyOf(req.Value) == model.FamilyIPv6 {
		return model.Result{}, fmt.Errorf("denyhosts: %q is IPv6; DenyHosts mishandles IPv6 — use a firewall backend", req.Value)
	}
	denyLine := servicePrefix + ": " + req.Value
	steps := []string{
		fmt.Sprintf("systemctl stop %s", b.service),
		fmt.Sprintf("append %q to %s", denyLine, b.hostsDeny),
		fmt.Sprintf("append %q to %s", req.Value, b.workFile("hosts")),
		fmt.Sprintf("append %q to %s", req.Value, b.workFile("hosts-restricted")),
		fmt.Sprintf("systemctl start %s", b.service),
	}
	res := model.Result{Backend: string(model.OriginDenyHosts), Action: "ban", Value: req.Value, Commands: steps, DryRun: req.DryRun}
	if req.DryRun {
		res.Message = "dry-run: not executed"
		return res, nil
	}
	b.stopService(ctx)
	if err := appendLine(b.hostsDeny, denyLine); err != nil {
		return res, err
	}
	if err := appendLine(b.workFile("hosts"), req.Value); err != nil {
		return res, err
	}
	if err := appendLine(b.workFile("hosts-restricted"), req.Value); err != nil {
		return res, err
	}
	b.startService(ctx)
	res.Changed = true
	return res, nil
}

// Unban removes the IP from hosts.deny and both work files, bracketed by a
// daemon stop/start so DenyHosts does not re-write the line on shutdown.
func (b *Backend) Unban(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	steps := []string{
		fmt.Sprintf("systemctl stop %s", b.service),
		fmt.Sprintf("remove lines matching %q from %s", e.Value, b.hostsDeny),
		fmt.Sprintf("remove lines matching %q from %s", e.Value, b.workFile("hosts")),
		fmt.Sprintf("remove lines matching %q from %s", e.Value, b.workFile("hosts-restricted")),
		fmt.Sprintf("systemctl start %s", b.service),
	}
	res := model.Result{Backend: string(model.OriginDenyHosts), Action: "unban", Value: e.Value, Commands: steps, DryRun: dryRun}
	if dryRun {
		res.Message = "dry-run: not executed"
		return res, nil
	}
	b.stopService(ctx)
	for _, path := range []string{b.hostsDeny, b.workFile("hosts"), b.workFile("hosts-restricted")} {
		if err := removeLines(path, e.Value); err != nil {
			return res, err
		}
	}
	b.startService(ctx)
	res.Changed = true
	return res, nil
}

// Allow adds the value to the DenyHosts allowed-hosts file.
func (b *Backend) Allow(_ context.Context, req model.ActionRequest) (model.Result, error) {
	res := model.Result{
		Backend:  string(model.OriginDenyHosts),
		Action:   "allow",
		Value:    req.Value,
		Commands: []string{fmt.Sprintf("append %q to %s", req.Value, b.allowedHosts)},
		DryRun:   req.DryRun,
	}
	if req.DryRun {
		res.Message = "dry-run: not executed"
		return res, nil
	}
	if err := appendLine(b.allowedHosts, req.Value); err != nil {
		return res, err
	}
	res.Changed = true
	return res, nil
}

// RemoveAllow removes the value from the DenyHosts allowed-hosts file.
func (b *Backend) RemoveAllow(_ context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	res := model.Result{
		Backend:  string(model.OriginDenyHosts),
		Action:   "unallow",
		Value:    e.Value,
		Commands: []string{fmt.Sprintf("remove lines matching %q from %s", e.Value, b.allowedHosts)},
		DryRun:   dryRun,
	}
	if dryRun {
		res.Message = "dry-run: not executed"
		return res, nil
	}
	if err := removeLines(b.allowedHosts, e.Value); err != nil {
		return res, err
	}
	res.Changed = true
	return res, nil
}

// --- helpers ---------------------------------------------------------------

func (b *Backend) workFile(name string) string {
	return b.workDir + "/" + name
}

// stopService best-effort-stops the daemon so it does not rewrite our edits.
// Failures (no systemd, init.d-managed, or an inactive service) are non-fatal:
// we proceed with the file edits regardless.
func (b *Backend) stopService(ctx context.Context) {
	_, _ = b.r.Run(ctx, "systemctl", "stop", b.service)
}

// startService best-effort-restarts the daemon after the edits.
func (b *Backend) startService(ctx context.Context) {
	_, _ = b.r.Run(ctx, "systemctl", "start", b.service)
}

// readLines returns the file split into lines. A missing file is not an error:
// it reports an empty list so listing a host without prior bans is clean.
func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	trimmed := strings.TrimRight(string(data), "\n")
	if trimmed == "" {
		return nil, nil
	}
	return strings.Split(trimmed, "\n"), nil
}

// appendLine appends line to path (creating it when absent), backing up an
// existing file first. It is idempotent: an exact existing line is left alone.
func appendLine(path, line string) error {
	lines, err := readLines(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	for _, l := range lines {
		if strings.TrimSpace(l) == strings.TrimSpace(line) {
			return nil // already present
		}
	}
	if err := backup(path); err != nil {
		return err
	}
	lines = append(lines, line)
	return writeLines(path, lines)
}

// removeLines rewrites path without any line containing the exact ip token,
// backing up the file first. A missing file is a no-op.
func removeLines(path, ip string) error {
	lines, err := readLines(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(lines) == 0 {
		return nil
	}
	kept := make([]string, 0, len(lines))
	changed := false
	for _, l := range lines {
		if containsToken(l, ip) {
			changed = true
			continue
		}
		kept = append(kept, l)
	}
	if !changed {
		return nil
	}
	if err := backup(path); err != nil {
		return err
	}
	return writeLines(path, kept)
}

// containsToken reports whether line contains ip as a whitespace/colon-delimited
// token, so removing "1.2.3.4" does not also drop "1.2.3.40".
func containsToken(line, ip string) bool {
	for _, f := range strings.FieldsFunc(line, func(r rune) bool {
		return r == ' ' || r == '\t' || r == ':'
	}) {
		if f == ip {
			return true
		}
	}
	return false
}

// writeLines writes lines to path with a trailing newline, preserving the file
// mode when it already exists.
func writeLines(path string, lines []string) error {
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	var sb strings.Builder
	for _, l := range lines {
		sb.WriteString(l)
		sb.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(sb.String()), mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// backup copies an existing file to "<path>.omniban.bak" before it is edited.
func backup(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", path, err)
	}
	mode := os.FileMode(0o644)
	if fi, serr := os.Stat(path); serr == nil {
		mode = fi.Mode().Perm()
	}
	if err := os.WriteFile(path+".omniban.bak", data, mode); err != nil {
		return fmt.Errorf("backup %s: %w", path, err)
	}
	return nil
}

func scopeOf(value string) model.Scope {
	if strings.Contains(value, "/") {
		return model.ScopeRange
	}
	return model.ScopeIP
}

func familyOf(value string) model.Family {
	if addr, err := netip.ParseAddr(value); err == nil {
		if addr.Is6() && !addr.Is4In6() {
			return model.FamilyIPv6
		}
		return model.FamilyIPv4
	}
	if p, err := netip.ParsePrefix(value); err == nil {
		if p.Addr().Is6() && !p.Addr().Is4In6() {
			return model.FamilyIPv6
		}
		return model.FamilyIPv4
	}
	return ""
}
