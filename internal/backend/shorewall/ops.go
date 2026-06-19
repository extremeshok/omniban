// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package shorewall

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/model"
)

// errNoBinary is returned by mutations when the shorewall CLI cannot be located.
var errNoBinary = errors.New("shorewall: binary not found (looked for shorewall)")

// blockTargets are the iptables targets that represent an active block in the
// dynamic chain.
var blockTargets = map[string]bool{"DROP": true, "REJECT": true}

// ListBans returns the IPs/CIDRs in Shorewall's dynamic blacklist by parsing
// "shorewall show dynamic".
//
// IPv6 entries live in shorewall6's dynamic chain; this adapter drives the IPv4
// "shorewall" binary only, so it reports the IPv4 dynamic blacklist. Operators
// needing IPv6 should add a shorewall6 backend (tracked for a later milestone).
func (b *Backend) ListBans(ctx context.Context) ([]model.Entry, error) {
	bin := b.bin()
	if bin == "" {
		return nil, errNoBinary
	}
	res, err := b.r.Run(ctx, bin, "show", "dynamic")
	if err != nil {
		return nil, fmt.Errorf("shorewall show dynamic: %w", err)
	}
	return parseDynamic(res.Stdout), nil
}

// parseDynamic extracts source addresses from DROP/REJECT lines of the dynamic
// chain listing. Lines look like:
//
//	pkts bytes target     prot opt in     out     source               destination
//	  12   720 DROP       all  --  *      *       1.2.3.4              0.0.0.0/0
//
// The source column (index 7) carries the banned IP/CIDR. Header, counter, and
// non-block lines are skipped, as is anything whose source does not parse as an
// address or prefix.
func parseDynamic(data []byte) []model.Entry {
	var out []model.Entry
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 8 {
			continue
		}
		if !blockTargets[fields[2]] {
			continue
		}
		src := fields[7]
		fam := familyOf(src)
		if fam == "" {
			continue
		}
		out = append(out, model.Entry{
			Value:     src,
			Family:    fam,
			Scope:     scopeOf(src),
			Kind:      model.KindBan,
			Direction: model.DirInbound,
			Origin:    model.OriginShorewall,
			Backend:   string(model.OriginShorewall),
			Detail:    fields[2],
			Raw:       strings.TrimSpace(sc.Text()),
		})
	}
	return out
}

// Ban adds the value to Shorewall's dynamic blacklist via "shorewall drop".
func (b *Backend) Ban(ctx context.Context, req model.ActionRequest) (model.Result, error) {
	bin := b.bin()
	if bin == "" {
		return model.Result{}, errNoBinary
	}
	return b.run(ctx, req.DryRun, "ban", req.Value, cmd(bin, []string{"drop", req.Value}))
}

// Unban removes the value from the dynamic blacklist. Shorewall has no direct
// "remove from blacklist" verb; "shorewall allow" deletes the dynamic
// drop/reject rule for the address (it does not create a persistent allow).
func (b *Backend) Unban(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	bin := b.bin()
	if bin == "" {
		return model.Result{}, errNoBinary
	}
	return b.run(ctx, dryRun, "unban", e.Value, cmd(bin, []string{"allow", e.Value}))
}

// Reload persists the in-memory dynamic blacklist so it survives a reboot
// ("shorewall save"). Best-effort: a missing binary is reported, but callers
// treat persistence failures as non-fatal.
func (b *Backend) Reload(ctx context.Context) error {
	bin := b.bin()
	if bin == "" {
		return errNoBinary
	}
	if _, err := b.r.Run(ctx, bin, "save"); err != nil {
		return fmt.Errorf("%s save: %w", bin, err)
	}
	return nil
}

// run executes (or, in dry-run, only records) a single command, returning a
// Result whose Commands field holds the exact invocation.
func (b *Backend) run(ctx context.Context, dryRun bool, action, value string, c []string) (model.Result, error) {
	res := model.Result{Backend: string(model.OriginShorewall), Action: action, Value: value, DryRun: dryRun}
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

// bin resolves the shorewall binary on PATH.
func (b *Backend) bin() string {
	return backend.FirstInstalled(b.r, "shorewall")
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
