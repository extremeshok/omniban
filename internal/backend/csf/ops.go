// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package csf

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/model"
)

// errNoBinary is returned by mutations when the csf CLI cannot be located.
var errNoBinary = errors.New("csf: binary not found (looked for csf, /usr/sbin/csf)")

// ListBans reads csf.deny and reports each entry as an inbound ban.
func (b *Backend) ListBans(_ context.Context) ([]model.Entry, error) {
	return b.parseFile(b.denyFile, model.KindBan, "")
}

// ListAllows reads csf.allow (and csf.ignore, the never-block list) and reports
// each entry as an inbound allow.
func (b *Backend) ListAllows(_ context.Context) ([]model.Entry, error) {
	allows, err := b.parseFile(b.allowFile, model.KindAllow, "")
	if err != nil {
		return nil, err
	}
	ignores, err := b.parseFile(b.ignoreFile, model.KindAllow, "ignore")
	if err != nil {
		return nil, err
	}
	return append(allows, ignores...), nil
}

// parseFile reads a CSF list file: each non-empty, non-comment line begins with
// an IP/CIDR token; the remainder of the line is the detail (often "# comment").
// A missing file is treated as empty. When detail is non-empty it overrides the
// per-line detail (used to tag csf.ignore entries).
func (b *Backend) parseFile(path string, kind model.Kind, detail string) ([]model.Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var out []model.Entry
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		token := line
		rest := ""
		if i := strings.IndexFunc(line, func(r rune) bool { return r == ' ' || r == '\t' }); i >= 0 {
			token = line[:i]
			rest = strings.TrimSpace(line[i+1:])
		}
		fam := familyOf(token)
		if fam == "" {
			continue
		}
		d := detail
		if d == "" {
			d = rest
		}
		out = append(out, model.Entry{
			Value:     token,
			Family:    fam,
			Scope:     scopeOf(token),
			Kind:      kind,
			Direction: model.DirInbound,
			Origin:    model.OriginCSF,
			Backend:   string(model.OriginCSF),
			Detail:    d,
			Raw:       line,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return out, nil
}

// Ban adds a deny entry via the csf CLI. A positive Duration uses a temporary
// deny (-td) for the given number of seconds; otherwise a permanent deny (-d).
func (b *Backend) Ban(ctx context.Context, req model.ActionRequest) (model.Result, error) {
	bin := b.bin()
	if bin == "" {
		return model.Result{}, errNoBinary
	}
	comment := "omniban: " + req.Reason
	var args []string
	if req.Duration > 0 {
		secs := strconv.FormatInt(int64(req.Duration.Seconds()), 10)
		args = []string{"-td", req.Value, secs, comment}
	} else {
		args = []string{"-d", req.Value, comment}
	}
	return b.run(ctx, req.DryRun, "ban", req.Value, cmd(bin, args))
}

// Unban removes a deny entry via the csf CLI (-dr).
func (b *Backend) Unban(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	bin := b.bin()
	if bin == "" {
		return model.Result{}, errNoBinary
	}
	return b.run(ctx, dryRun, "unban", e.Value, cmd(bin, []string{"-dr", e.Value}))
}

// Allow adds an allow entry via the csf CLI (-a).
func (b *Backend) Allow(ctx context.Context, req model.ActionRequest) (model.Result, error) {
	bin := b.bin()
	if bin == "" {
		return model.Result{}, errNoBinary
	}
	comment := "omniban: " + req.Reason
	return b.run(ctx, req.DryRun, "allow", req.Value, cmd(bin, []string{"-a", req.Value, comment}))
}

// RemoveAllow removes an allow entry via the csf CLI (-ar).
func (b *Backend) RemoveAllow(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	bin := b.bin()
	if bin == "" {
		return model.Result{}, errNoBinary
	}
	return b.run(ctx, dryRun, "unallow", e.Value, cmd(bin, []string{"-ar", e.Value}))
}

// Reload applies pending changes (csf -r).
func (b *Backend) Reload(ctx context.Context) error {
	bin := b.bin()
	if bin == "" {
		return errNoBinary
	}
	if _, err := b.r.Run(ctx, bin, "-r"); err != nil {
		return fmt.Errorf("%s -r: %w", bin, err)
	}
	return nil
}

// run executes (or, in dry-run, only records) a single command, returning a
// Result whose Commands field holds the exact invocation.
func (b *Backend) run(ctx context.Context, dryRun bool, action, value string, c []string) (model.Result, error) {
	res := model.Result{Backend: string(model.OriginCSF), Action: action, Value: value, DryRun: dryRun}
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

// bin resolves the csf binary, preferring PATH then the common sbin location.
func (b *Backend) bin() string {
	return backend.FirstInstalled(b.r, "csf", "/usr/sbin/csf")
}

func cmd(name string, args []string) []string {
	return append([]string{name}, args...)
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
