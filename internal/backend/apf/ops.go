// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

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

// Unban removes a deny entry via "apf -u", which deletes the host from the
// rule files.
func (b *Backend) Unban(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	bin := b.bin()
	if bin == "" {
		return model.Result{}, errNoBinary
	}
	c := cmd(bin, "-u", e.Value)
	return b.run(ctx, dryRun, "unban", e.Value, [][]string{c})
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

// RemoveAllow removes an allow entry via "apf -u". APF's -u removes the host
// from the rule files (both deny and allow), so the same flag covers unallow.
func (b *Backend) RemoveAllow(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	bin := b.bin()
	if bin == "" {
		return model.Result{}, errNoBinary
	}
	c := cmd(bin, "-u", e.Value)
	return b.run(ctx, dryRun, "unallow", e.Value, [][]string{c})
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
