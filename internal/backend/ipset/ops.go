// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package ipset

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/extremeshok/omniban/internal/config"
	"github.com/extremeshok/omniban/internal/model"
)

// ownedSet pairs an omniban-owned set name with its ipset family token and the
// iptables tool that installs the referencing DROP rule.
type ownedSet struct {
	name   string // config.IPSetDeny4 / config.IPSetDeny6
	family string // "inet" / "inet6"
	tool   string // "iptables" / "ip6tables"
}

// Overridable command names, so tests can pin exact invocations.
var (
	ipsetBin     = "ipset"
	iptablesBin  = "iptables"
	ip6tablesBin = "ip6tables"
)

// owned4/owned6 describe the two sets omniban manages.
func owned4() ownedSet {
	return ownedSet{name: config.IPSetDeny4, family: "inet", tool: iptablesBin}
}

func owned6() ownedSet {
	return ownedSet{name: config.IPSetDeny6, family: "inet6", tool: ip6tablesBin}
}

// setFor returns the owned set matching the value's address family.
func setFor(value string) ownedSet {
	if familyOf(value) == model.FamilyIPv6 {
		return owned6()
	}
	return owned4()
}

// ListBans reads both omniban-owned sets via "ipset save" and reports each
// element as an inbound ban. A missing set yields no entries.
func (b *Backend) ListBans(ctx context.Context) ([]model.Entry, error) {
	var out []model.Entry
	for _, s := range []ownedSet{owned4(), owned6()} {
		res, err := b.r.Run(ctx, ipsetBin, "save", s.name)
		if err != nil {
			// Tolerate a missing set (non-zero exit) as empty.
			continue
		}
		out = append(out, parseSave(res.Stdout)...)
	}
	return out, nil
}

// parseSave parses "ipset save" output, extracting "add <set> <value> ..."
// lines. The third whitespace-separated field is the element value.
func parseSave(data []byte) []model.Entry {
	var out []model.Entry
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.HasPrefix(line, "add ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		value := fields[2]
		fam := familyOf(value)
		if fam == "" {
			continue
		}
		out = append(out, model.Entry{
			Value:     value,
			Family:    fam,
			Scope:     scopeOf(value),
			Kind:      model.KindBan,
			Direction: model.DirInbound,
			Origin:    model.OriginIPSet,
			Backend:   string(model.OriginIPSet),
			Raw:       line,
		})
	}
	return out
}

// Ban ensures the owned set and its referencing DROP rule exist, then adds the
// value as a set element.
func (b *Backend) Ban(ctx context.Context, req model.ActionRequest) (model.Result, error) {
	s := setFor(req.Value)
	add := cmd(ipsetBin, []string{"add", "-exist", s.name, req.Value})

	res := model.Result{
		Backend: string(model.OriginIPSet),
		Action:  "ban",
		Value:   req.Value,
		DryRun:  req.DryRun,
	}
	res.Commands = scaffoldCommands(s)
	res.Commands = append(res.Commands, strings.Join(add, " "))
	if req.DryRun {
		res.Message = "dry-run: not executed"
		return res, nil
	}
	if err := b.ensureScaffold(ctx, s); err != nil {
		return res, err
	}
	if _, err := b.r.Run(ctx, add[0], add[1:]...); err != nil {
		return res, fmt.Errorf("%s: %w", strings.Join(add, " "), err)
	}
	res.Changed = true
	return res, nil
}

// Unban removes the value from its owned set.
func (b *Backend) Unban(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	s := setFor(e.Value)
	del := cmd(ipsetBin, []string{"del", "-exist", s.name, e.Value})

	res := model.Result{
		Backend:  string(model.OriginIPSet),
		Action:   "unban",
		Value:    e.Value,
		DryRun:   dryRun,
		Commands: []string{strings.Join(del, " ")},
	}
	if dryRun {
		res.Message = "dry-run: not executed"
		return res, nil
	}
	if _, err := b.r.Run(ctx, del[0], del[1:]...); err != nil {
		return res, fmt.Errorf("%s: %w", strings.Join(del, " "), err)
	}
	res.Changed = true
	return res, nil
}

// Reload is a no-op: persistence is handled by the boot unit (ipset save) added
// later. Returning nil keeps callers happy without touching foreign state.
func (b *Backend) Reload(_ context.Context) error { return nil }

// ensureScaffold idempotently creates the owned set and the iptables/ip6tables
// DROP rule that references it. It is check-or-create: existing objects are left
// untouched and never error.
func (b *Backend) ensureScaffold(ctx context.Context, s ownedSet) error {
	// Create the set if it does not already exist.
	if _, err := b.r.Run(ctx, ipsetBin, "list", s.name); err != nil {
		create := cmd(ipsetBin, []string{"create", s.name, "hash:net", "family", s.family, "-exist"})
		if _, cerr := b.r.Run(ctx, create[0], create[1:]...); cerr != nil {
			return fmt.Errorf("%s: %w", strings.Join(create, " "), cerr)
		}
	}
	// Ensure the referencing DROP rule on the INPUT chain.
	checkRule := matchSetRule(s.tool, "-C", s.name)
	if _, err := b.r.Run(ctx, checkRule[0], checkRule[1:]...); err != nil {
		insertRule := matchSetRule(s.tool, "-I", s.name)
		if _, ierr := b.r.Run(ctx, insertRule[0], insertRule[1:]...); ierr != nil {
			return fmt.Errorf("%s: %w", strings.Join(insertRule, " "), ierr)
		}
	}
	return nil
}

// scaffoldCommands returns the shell-equivalent invocations ensureScaffold may
// run, for the Result.Commands trace (dry-run and executed alike).
func scaffoldCommands(s ownedSet) []string {
	return []string{
		strings.Join(cmd(ipsetBin, []string{"list", s.name}), " "),
		strings.Join(cmd(ipsetBin, []string{"create", s.name, "hash:net", "family", s.family, "-exist"}), " "),
		strings.Join(matchSetRule(s.tool, "-C", s.name), " "),
		strings.Join(matchSetRule(s.tool, "-I", s.name), " "),
	}
}

// matchSetRule builds an iptables/ip6tables INPUT rule referencing the set.
// op is "-C" (check) or "-I" (insert).
func matchSetRule(tool, op, set string) []string {
	return cmd(tool, []string{op, "INPUT", "-m", "set", "--match-set", set, "src", "-j", "DROP"})
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
