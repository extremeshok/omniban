// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package blackhole

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/extremeshok/omniban/internal/model"
)

// ListBans reports the kernel blackhole routes (IPv4 and IPv6). These drop all
// traffic to the destination, so the direction is "both".
func (b *Backend) ListBans(ctx context.Context) ([]model.Entry, error) {
	var out []model.Entry
	for _, fam := range []struct {
		v6   bool
		args []string
	}{
		{false, []string{"route", "show", "type", "blackhole"}},
		{true, []string{"-6", "route", "show", "type", "blackhole"}},
	} {
		res, err := b.r.Run(ctx, "ip", fam.args...)
		if err != nil {
			continue // tolerate (e.g. no v6) — a family with no routes is not an error
		}
		for _, line := range strings.Split(res.Out(), "\n") {
			value := parseBlackholeLine(line)
			if value == "" {
				continue
			}
			out = append(out, model.Entry{
				Value:     value,
				Family:    familyOf(value),
				Scope:     scopeOf(value),
				Kind:      model.KindBan,
				Direction: model.DirBoth,
				Origin:    model.OriginBlackhole,
				Backend:   string(model.OriginBlackhole),
				Raw:       strings.TrimSpace(line),
			})
		}
	}
	return out, nil
}

// Ban installs a blackhole route for the IP/CIDR and persists it for boot replay.
func (b *Backend) Ban(ctx context.Context, req model.ActionRequest) (model.Result, error) {
	value, v6, err := normalize(req.Value)
	if err != nil {
		return model.Result{}, err
	}
	args := ipArgs(v6, "route", "add", "blackhole", value)
	res := b.result("ban", value, [][]string{cmdIP(args)})
	if req.DryRun {
		res.Commands = append(res.Commands, fmt.Sprintf("persist %s to %s", value, b.routesFile))
		res.DryRun = true
		res.Message = "dry-run: not executed"
		return res, nil
	}
	if _, err := b.r.Run(ctx, "ip", args...); err != nil {
		return res, fmt.Errorf("ip %s: %w", strings.Join(args, " "), err)
	}
	if err := b.persistAdd(value); err != nil {
		return res, err
	}
	res.Changed = true
	return res, nil
}

// Unban removes the blackhole route and drops it from the persisted set.
func (b *Backend) Unban(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	value, v6, err := normalize(e.Value)
	if err != nil {
		return model.Result{}, err
	}
	args := ipArgs(v6, "route", "del", "blackhole", value)
	res := b.result("unban", value, [][]string{cmdIP(args)})
	if dryRun {
		res.DryRun = true
		res.Message = "dry-run: not executed"
		return res, nil
	}
	if _, err := b.r.Run(ctx, "ip", args...); err != nil {
		return res, fmt.Errorf("ip %s: %w", strings.Join(args, " "), err)
	}
	if err := b.persistRemove(value); err != nil {
		return res, err
	}
	res.Changed = true
	return res, nil
}

// Apply replays the persisted blackhole routes (called at boot by the systemd
// oneshot via `omniban apply-routes`). Existing routes are skipped.
func (b *Backend) Apply(ctx context.Context) error {
	lines, err := readLines(b.routesFile)
	if err != nil {
		return err
	}
	for _, line := range lines {
		value, v6, nerr := normalize(line)
		if nerr != nil {
			continue
		}
		// "ip route add" fails if it already exists; ignore that error.
		_, _ = b.r.Run(ctx, "ip", ipArgs(v6, "route", "add", "blackhole", value)...)
	}
	return nil
}

// --- helpers ---------------------------------------------------------------

func (b *Backend) result(action, value string, cmds [][]string) model.Result {
	r := model.Result{Backend: string(model.OriginBlackhole), Action: action, Value: value}
	for _, c := range cmds {
		r.Commands = append(r.Commands, strings.Join(c, " "))
	}
	return r
}

func cmdIP(args []string) []string { return append([]string{"ip"}, args...) }

func ipArgs(v6 bool, args ...string) []string {
	if v6 {
		return append([]string{"-6"}, args...)
	}
	return args
}

// normalize returns the masked CIDR/host string and whether it is IPv6.
func normalize(value string) (string, bool, error) {
	value = strings.TrimSpace(value)
	if addr, err := netip.ParseAddr(value); err == nil {
		addr = addr.Unmap()
		return addr.String(), addr.Is6(), nil
	}
	if p, err := netip.ParsePrefix(value); err == nil {
		p = p.Masked()
		return p.String(), p.Addr().Is6(), nil
	}
	return "", false, fmt.Errorf("blackhole: %q is not an IP or CIDR", value)
}

func parseBlackholeLine(line string) string {
	fields := strings.Fields(line)
	if len(fields) >= 2 && fields[0] == "blackhole" {
		return fields[1]
	}
	return ""
}

func (b *Backend) persistAdd(value string) error {
	lines, err := readLines(b.routesFile)
	if err != nil {
		return err
	}
	for _, l := range lines {
		if strings.TrimSpace(l) == value {
			return nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(b.routesFile), 0o755); err != nil {
		return err
	}
	lines = append(lines, value)
	return writeLines(b.routesFile, lines)
}

func (b *Backend) persistRemove(value string) error {
	lines, err := readLines(b.routesFile)
	if err != nil || len(lines) == 0 {
		return err
	}
	kept := make([]string, 0, len(lines))
	for _, l := range lines {
		if strings.TrimSpace(l) != value {
			kept = append(kept, l)
		}
	}
	return writeLines(b.routesFile, kept)
}

func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out, nil
}

func writeLines(path string, lines []string) error {
	var sb strings.Builder
	for _, l := range lines {
		sb.WriteString(l)
		sb.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
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
