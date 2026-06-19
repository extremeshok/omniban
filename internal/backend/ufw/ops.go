// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package ufw

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/extremeshok/omniban/internal/model"
)

// ListBans returns DENY/REJECT source rules reported by `ufw status numbered`.
func (b *Backend) ListBans(ctx context.Context) ([]model.Entry, error) {
	return b.list(ctx, model.KindBan)
}

// ListAllows returns ALLOW source rules reported by `ufw status numbered`.
func (b *Backend) ListAllows(ctx context.Context) ([]model.Entry, error) {
	return b.list(ctx, model.KindAllow)
}

// list runs `ufw status numbered` and returns the rows whose action matches
// kind (DENY/REJECT -> ban, ALLOW -> allow) and whose source is a bare IP/CIDR.
func (b *Backend) list(ctx context.Context, kind model.Kind) ([]model.Entry, error) {
	res, err := b.r.Run(ctx, "ufw", "status", "numbered")
	if err != nil {
		return nil, fmt.Errorf("ufw status numbered: %w", err)
	}
	return parseStatus(res.Stdout, kind), nil
}

// parseStatus parses `ufw status numbered` output, returning only rows whose
// action maps to kind and whose source (the last field) is an IP or CIDR. Rows
// with a source of "Anywhere" or a port-only rule are skipped.
func parseStatus(data []byte, kind model.Kind) []model.Entry {
	var out []model.Entry
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		rowKind, ok := actionKind(line)
		if !ok || rowKind != kind {
			continue
		}
		src := lastField(line)
		fam := familyOf(src)
		if fam == "" {
			// "Anywhere", port-only, or any non-address source.
			continue
		}
		out = append(out, model.Entry{
			Value:     src,
			Family:    fam,
			Scope:     scopeOf(src),
			Kind:      kind,
			Direction: model.DirInbound,
			Origin:    model.OriginUFW,
			Backend:   string(model.OriginUFW),
			Raw:       line,
		})
	}
	return out
}

// Ban adds a deny-from rule (`ufw deny from <value>`).
func (b *Backend) Ban(ctx context.Context, req model.ActionRequest) (model.Result, error) {
	return b.run(ctx, req.DryRun, "ban", req.Value,
		[]string{"ufw", "deny", "from", req.Value})
}

// Unban removes the matching deny rule by specification (`ufw delete deny from
// <value>`), which avoids the renumber-on-delete hazard of numbered deletes.
func (b *Backend) Unban(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	return b.run(ctx, dryRun, "unban", e.Value,
		[]string{"ufw", "delete", "deny", "from", e.Value})
}

// Allow adds an allow-from rule (`ufw allow from <value>`).
func (b *Backend) Allow(ctx context.Context, req model.ActionRequest) (model.Result, error) {
	return b.run(ctx, req.DryRun, "allow", req.Value,
		[]string{"ufw", "allow", "from", req.Value})
}

// RemoveAllow removes the matching allow rule by specification (`ufw delete
// allow from <value>`).
func (b *Backend) RemoveAllow(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	return b.run(ctx, dryRun, "unallow", e.Value,
		[]string{"ufw", "delete", "allow", "from", e.Value})
}

// run executes (or, in dry-run, only records) a single command, returning a
// Result whose Commands field holds the exact invocation.
func (b *Backend) run(ctx context.Context, dryRun bool, action, value string, c []string) (model.Result, error) {
	res := model.Result{Backend: string(model.OriginUFW), Action: action, Value: value, DryRun: dryRun}
	res.Commands = append(res.Commands, strings.Join(c, " "))
	if dryRun {
		res.Message = "dry-run: not executed"
		return res, nil
	}
	if _, err := b.r.Run(ctx, c[0], c[1:]...); err != nil {
		return res, fmt.Errorf("%s: %w", strings.Join(c, " "), err)
	}
	res.Changed = true
	return res, nil
}

// actionKind reports the ban/allow kind implied by a status row's action token
// (DENY/REJECT -> ban, ALLOW -> allow). ok is false when the row carries no
// recognized action.
func actionKind(line string) (model.Kind, bool) {
	upper := strings.ToUpper(line)
	switch {
	case strings.Contains(upper, "DENY"), strings.Contains(upper, "REJECT"):
		return model.KindBan, true
	case strings.Contains(upper, "ALLOW"):
		return model.KindAllow, true
	default:
		return "", false
	}
}

// lastField returns the final whitespace-separated token of line.
func lastField(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
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
