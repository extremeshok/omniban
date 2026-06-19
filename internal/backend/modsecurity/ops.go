// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package modsecurity

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/extremeshok/omniban/internal/model"
)

// ListBans reads the managed @ipMatchFromFile blocklist (one IP/CIDR per line,
// blank and #-comment lines skipped) and reports each as an inbound ban.
func (b *Backend) ListBans(_ context.Context) ([]model.Entry, error) {
	lines, err := readLines(b.blocklist)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", b.blocklist, err)
	}
	out := make([]model.Entry, 0, len(lines))
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// A blocklist line may carry a trailing comment; the token is field one.
		token := line
		if i := strings.IndexFunc(line, func(r rune) bool { return r == ' ' || r == '\t' }); i >= 0 {
			token = line[:i]
		}
		fam := familyOf(token)
		if fam == "" {
			continue
		}
		out = append(out, model.Entry{
			Value:     token,
			Family:    fam,
			Scope:     scopeOf(token),
			Kind:      model.KindBan,
			Direction: model.DirInbound,
			Origin:    model.OriginModSecurity,
			Backend:   string(model.OriginModSecurity),
			Raw:       line,
		})
	}
	return out, nil
}

// Ban appends the value to the blocklist (idempotent, backing the file up
// first) and reloads the web server to apply it. On dry-run it records both
// steps and writes nothing.
func (b *Backend) Ban(ctx context.Context, req model.ActionRequest) (model.Result, error) {
	value := strings.TrimSpace(req.Value)
	res := model.Result{
		Backend: string(model.OriginModSecurity),
		Action:  "ban",
		Value:   value,
		Commands: []string{
			fmt.Sprintf("append %q to %s", value, b.blocklist),
			b.reloadBin + " -s reload",
		},
		DryRun: req.DryRun,
	}
	if req.DryRun {
		res.Message = "dry-run: not executed"
		return res, nil
	}
	added, err := appendLine(b.blocklist, value)
	if err != nil {
		return res, err
	}
	if !added {
		res.Message = "already present"
		return res, nil
	}
	if err := b.reload(ctx); err != nil {
		return res, err
	}
	res.Changed = true
	return res, nil
}

// Unban removes the matching line (token boundary) from the blocklist, backing
// the file up first, then reloads the web server. On dry-run it records both
// steps and writes nothing.
func (b *Backend) Unban(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	value := strings.TrimSpace(e.Value)
	res := model.Result{
		Backend: string(model.OriginModSecurity),
		Action:  "unban",
		Value:   value,
		Commands: []string{
			fmt.Sprintf("remove lines matching %q from %s", value, b.blocklist),
			b.reloadBin + " -s reload",
		},
		DryRun: dryRun,
	}
	if dryRun {
		res.Message = "dry-run: not executed"
		return res, nil
	}
	removed, err := removeLines(b.blocklist, value)
	if err != nil {
		return res, err
	}
	if !removed {
		res.Message = "not present"
		return res, nil
	}
	if err := b.reload(ctx); err != nil {
		return res, err
	}
	res.Changed = true
	return res, nil
}

// Reload applies pending changes by reloading the web server.
func (b *Backend) Reload(ctx context.Context) error {
	return b.reload(ctx)
}

// reload signals the web server to reload its configuration ("nginx -s reload").
func (b *Backend) reload(ctx context.Context) error {
	if _, err := b.r.Run(ctx, b.reloadBin, "-s", "reload"); err != nil {
		return fmt.Errorf("%s -s reload: %w", b.reloadBin, err)
	}
	return nil
}

// --- helpers ---------------------------------------------------------------

// readLines returns the file split into lines. A missing file is not an error:
// it reports an empty list so listing before any ban is clean.
func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-configured blocklist path
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

// appendLine appends value to path (creating it when absent), backing up an
// existing file first. It is idempotent: an exact existing token is left alone.
// It reports whether the line was added.
func appendLine(path, value string) (bool, error) {
	lines, err := readLines(path)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	for _, l := range lines {
		if containsToken(l, value) {
			return false, nil // already present
		}
	}
	if err := backup(path); err != nil {
		return false, err
	}
	lines = append(lines, value)
	if err := writeLines(path, lines); err != nil {
		return false, err
	}
	return true, nil
}

// removeLines rewrites path without any line whose first token equals value,
// backing the file up first. A missing file or absent value is a no-op. It
// reports whether anything was removed.
func removeLines(path, value string) (bool, error) {
	lines, err := readLines(path)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	if len(lines) == 0 {
		return false, nil
	}
	kept := make([]string, 0, len(lines))
	changed := false
	for _, l := range lines {
		if containsToken(l, value) {
			changed = true
			continue
		}
		kept = append(kept, l)
	}
	if !changed {
		return false, nil
	}
	if err := backup(path); err != nil {
		return false, err
	}
	if err := writeLines(path, kept); err != nil {
		return false, err
	}
	return true, nil
}

// containsToken reports whether line's first whitespace-delimited field equals
// value, so removing "1.2.3.4" does not also drop "1.2.3.40" or a comment that
// merely mentions the address.
func containsToken(line, value string) bool {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false
	}
	return fields[0] == value
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
	if err := os.WriteFile(path, []byte(sb.String()), mode); err != nil { //nolint:gosec // operator-configured blocklist path
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// backup copies an existing file to "<path>.omniban.bak" before it is edited.
func backup(path string) error {
	data, err := os.ReadFile(path) //nolint:gosec // operator-configured blocklist path
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
	if err := os.WriteFile(path+".omniban.bak", data, mode); err != nil { //nolint:gosec // operator-configured blocklist path
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
