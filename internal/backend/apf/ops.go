// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package apf

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/model"
)

// ListBans returns the deny entries parsed from APF's deny_hosts.rules file.
func (b *Backend) ListBans(_ context.Context) ([]model.Entry, error) {
	return b.parseFile(b.denyFile, model.KindBan)
}

// ListAllows returns the allow entries parsed from APF's allow_hosts.rules file.
func (b *Backend) ListAllows(_ context.Context) ([]model.Entry, error) {
	return b.parseFile(b.allowFile, model.KindAllow)
}

// parseFile reads an APF rule file and returns one Entry per deny/allow line.
// A missing file is treated as an empty list, not an error.
func (b *Backend) parseFile(path string, kind model.Kind) ([]model.Entry, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-configured rule-file path
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var out []model.Entry
	for _, line := range strings.Split(string(data), "\n") {
		raw := line
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		body, detail := splitComment(line)
		value := extractValue(body)
		if value == "" {
			continue
		}
		out = append(out, model.Entry{
			Value:     value,
			Family:    familyOf(value),
			Scope:     scopeOf(value),
			Kind:      kind,
			Direction: model.DirInbound,
			Origin:    model.OriginAPF,
			Backend:   string(model.OriginAPF),
			Detail:    detail,
			Raw:       strings.TrimRight(raw, "\r"),
		})
	}
	return out, nil
}

// Ban adds a deny rule via "apf -d". APF appends the host (and our reason
// comment) to deny_hosts.rules.
func (b *Backend) Ban(ctx context.Context, req model.ActionRequest) (model.Result, error) {
	bin := b.bin()
	if bin == "" {
		return model.Result{}, errNoBinary
	}
	c := cmd(bin, "-d", req.Value, "omniban: "+reasonOf(req.Reason))
	return b.run(ctx, req.DryRun, "ban", req.Value, [][]string{c})
}

// Unban removes a deny entry. APF's own "-u" does not reliably edit the rule
// file (and "-d" also leaves a "# added ..." comment line), so omniban removes
// every line referencing the value from deny_hosts.rules — the authoritative
// store that survives reloads — then best-effort runs "apf -u" to drop the live
// firewall rule.
func (b *Backend) Unban(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	return b.remove(ctx, dryRun, "unban", e.Value, b.denyFile)
}

// Allow adds an allow rule via "apf -a", which appends the host to
// allow_hosts.rules.
func (b *Backend) Allow(ctx context.Context, req model.ActionRequest) (model.Result, error) {
	bin := b.bin()
	if bin == "" {
		return model.Result{}, errNoBinary
	}
	c := cmd(bin, "-a", req.Value, "omniban: "+reasonOf(req.Reason))
	return b.run(ctx, req.DryRun, "allow", req.Value, [][]string{c})
}

// RemoveAllow removes an allow entry from allow_hosts.rules (authoritative),
// then best-effort runs "apf -u" to drop the live rule.
func (b *Backend) RemoveAllow(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	return b.remove(ctx, dryRun, "unallow", e.Value, b.allowFile)
}

// remove deletes every line referencing value from an APF rule file (backing it
// up first), then best-effort drops the live rule with "apf -u". omniban owns
// the file removal because APF's -u does not reliably edit the rule files.
func (b *Backend) remove(ctx context.Context, dryRun bool, action, value, file string) (model.Result, error) {
	res := model.Result{Backend: string(model.OriginAPF), Action: action, Value: value, DryRun: dryRun}
	res.Commands = append(res.Commands, fmt.Sprintf("remove lines matching %q from %s", value, file))
	bin := b.bin()
	if bin != "" {
		res.Commands = append(res.Commands, strings.Join(cmd(bin, "-u", value), " "))
	}
	if dryRun {
		res.Message = "dry-run: not executed"
		return res, nil
	}
	changed, err := removeFromFile(file, value)
	if err != nil {
		return res, err
	}
	if bin != "" {
		_, _ = b.r.Run(ctx, bin, "-u", value) // best-effort: drop the live firewall rule
	}
	res.Changed = changed
	if !changed {
		res.Message = "not present"
	}
	return res, nil
}

// errNoBinary is returned by mutations when the apf binary cannot be found.
var errNoBinary = fmt.Errorf("apf binary not found (looked for apf on PATH and %s)", apfBin)

// bin resolves the apf binary, preferring PATH then the canonical install path.
func (b *Backend) bin() string {
	return backend.FirstInstalled(b.r, "apf", apfBin)
}

// run executes (or, in dry-run, only records) one or more apf commands,
// returning a Result whose Commands field holds the exact invocations.
func (b *Backend) run(ctx context.Context, dryRun bool, action, value string, cmds [][]string) (model.Result, error) {
	res := model.Result{Backend: string(model.OriginAPF), Action: action, Value: value, DryRun: dryRun}
	for _, c := range cmds {
		res.Commands = append(res.Commands, strings.Join(c, " "))
	}
	if dryRun {
		res.Message = "dry-run: not executed"
		return res, nil
	}
	for _, c := range cmds {
		if _, err := b.r.Run(ctx, c[0], c[1:]...); err != nil {
			return res, fmt.Errorf("%s: %w", strings.Join(c, " "), err)
		}
	}
	res.Changed = true
	return res, nil
}

func cmd(name string, args ...string) []string {
	return append([]string{name}, args...)
}

// removeFromFile rewrites path without any line referencing value — both the
// bare rule line and the "# added <value> ..." comment APF writes — backing the
// file up first. A missing file is a no-op.
func removeFromFile(path, value string) (bool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-configured rule-file path
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
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
	if err := backupFile(path); err != nil {
		return false, err
	}
	return true, writeLines(path, kept)
}

// containsToken reports whether line contains value as a whitespace/':'/'='/'#'
// delimited token, so removing "1.2.3.4" does not also match "1.2.3.40".
func containsToken(line, value string) bool {
	for _, f := range strings.FieldsFunc(line, func(r rune) bool {
		return r == ' ' || r == '\t' || r == ':' || r == '=' || r == '#'
	}) {
		if f == value {
			return true
		}
	}
	return false
}

func backupFile(path string) error {
	data, err := os.ReadFile(path) //nolint:gosec // operator-configured rule-file path
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := os.WriteFile(path+".omniban.bak", data, 0o644); err != nil { //nolint:gosec // rule-file backup
		return fmt.Errorf("backup %s: %w", path, err)
	}
	return nil
}

func writeLines(path string, lines []string) error {
	out := strings.Join(lines, "\n")
	if out != "" {
		out += "\n"
	}
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil { //nolint:gosec // operator-configured rule-file path
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// reasonOf returns a non-empty reason for the omniban comment tag.
func reasonOf(reason string) string {
	if strings.TrimSpace(reason) == "" {
		return "manual"
	}
	return reason
}

// splitComment separates an APF rule line into its body and the trailing
// comment (the text after the first '#', trimmed). A bfd-tagged comment is
// preserved verbatim so attribution survives into Detail.
func splitComment(line string) (body, detail string) {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:])
	}
	return line, ""
}

// extractValue pulls the first IP or CIDR token from an APF rule body. Plain
// lines lead with the address; advanced lines (e.g. "d=22:s=5.6.7.0/24") embed
// it in an "s=<ip/cidr>" fragment, which we fall back to.
func extractValue(body string) string {
	body = strings.TrimSpace(body)
	if body == "" {
		return ""
	}
	fields := strings.Fields(body)
	if len(fields) > 0 && isIP(fields[0]) {
		return fields[0]
	}
	for _, f := range fields {
		for _, frag := range strings.Split(f, ":") {
			rest, ok := strings.CutPrefix(frag, "s=")
			if !ok {
				continue
			}
			if isIP(rest) {
				return rest
			}
		}
	}
	return ""
}

// isIP reports whether s parses as a bare IP or a CIDR prefix.
func isIP(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	_, err := netip.ParsePrefix(s)
	return err == nil
}

// scopeOf classifies a value as a single IP or a CIDR range.
func scopeOf(value string) model.Scope {
	if strings.Contains(value, "/") {
		if _, err := netip.ParsePrefix(value); err == nil {
			return model.ScopeRange
		}
	}
	return model.ScopeIP
}

// familyOf returns the address family of an IP or CIDR value.
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
