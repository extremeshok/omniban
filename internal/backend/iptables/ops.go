// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package iptables

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/extremeshok/omniban/internal/config"
	"github.com/extremeshok/omniban/internal/model"
)

// tool4/tool6 are the per-family iptables binaries omniban shells out to.
const (
	tool4 = "iptables"
	tool6 = "ip6tables"
)

// ListBans reads omniban's owned OMNIBAN_INPUT chain for both families and
// reports each DROP rule as an inbound ban. A non-existent chain (non-zero
// exit) is treated as empty.
func (b *Backend) ListBans(ctx context.Context) ([]model.Entry, error) {
	var out []model.Entry
	for _, tool := range []string{tool4, tool6} {
		res, err := b.r.Run(ctx, tool, "-S", config.IptablesChainIn)
		if err != nil {
			// A missing chain exits non-zero; treat the chain as empty.
			continue
		}
		out = append(out, parseSave(res.Out())...)
	}
	return out, nil
}

// parseSave extracts the -s value from each "-A OMNIBAN_INPUT -s <cidr> -j DROP"
// line emitted by "iptables -S OMNIBAN_INPUT".
func parseSave(data string) []model.Entry {
	var out []model.Entry
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// Expect: -A OMNIBAN_INPUT -s <value> -j DROP
		if len(fields) < 6 || fields[0] != "-A" || fields[1] != config.IptablesChainIn {
			continue
		}
		if fields[2] != "-s" || fields[4] != "-j" || fields[5] != "DROP" {
			continue
		}
		value := normalizeValue(fields[3])
		out = append(out, model.Entry{
			Value:     value,
			Family:    familyOf(value),
			Scope:     scopeOf(value),
			Kind:      model.KindBan,
			Direction: model.DirInbound,
			Origin:    model.OriginIptables,
			Backend:   string(model.OriginIptables),
			Raw:       strings.TrimSpace(sc.Text()),
		})
	}
	return out
}

// Ban appends a DROP rule for req.Value to the owned chain, ensuring the chain
// and its INPUT jump exist first.
func (b *Backend) Ban(ctx context.Context, req model.ActionRequest) (model.Result, error) {
	tool := toolFor(req.Value)
	scaffold := scaffoldCmds(tool)
	add := cmd(tool, []string{"-A", config.IptablesChainIn, "-s", req.Value, "-j", "DROP"})

	res := model.Result{Backend: string(model.OriginIptables), Action: "ban", Value: req.Value, DryRun: req.DryRun}
	res.Commands = append(res.Commands, joinAll(scaffold)...)
	res.Commands = append(res.Commands, strings.Join(add, " "))
	if req.DryRun {
		res.Message = "dry-run: not executed"
		return res, nil
	}
	if err := b.ensureScaffold(ctx, tool); err != nil {
		return res, err
	}
	if _, err := b.r.Run(ctx, add[0], add[1:]...); err != nil {
		return res, fmt.Errorf("%s: %w", strings.Join(add, " "), err)
	}
	res.Changed = true
	return res, nil
}

// Unban deletes the DROP rule for e.Value from the owned chain.
func (b *Backend) Unban(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	tool := toolFor(e.Value)
	del := cmd(tool, []string{"-D", config.IptablesChainIn, "-s", e.Value, "-j", "DROP"})

	res := model.Result{Backend: string(model.OriginIptables), Action: "unban", Value: e.Value, DryRun: dryRun}
	res.Commands = append(res.Commands, strings.Join(del, " "))
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

// Reload is a best-effort no-op: persistence of the owned chain (rules.v4/.v6 or
// netfilter-persistent save) is handled by the install's boot unit.
func (b *Backend) Reload(_ context.Context) error { return nil }

// ensureScaffold idempotently creates the owned chain and the INPUT jump rule.
// Creating an existing chain or checking an existing rule exits non-zero; those
// errors are tolerated.
func (b *Backend) ensureScaffold(ctx context.Context, tool string) error {
	// Create the chain; ignore the error when it already exists.
	_, _ = b.r.Run(ctx, tool, "-N", config.IptablesChainIn)
	// Jump from INPUT only if the reference rule is not already present.
	if _, err := b.r.Run(ctx, tool, "-C", "INPUT", "-j", config.IptablesChainIn); err != nil {
		ins := []string{"-I", "INPUT", "-j", config.IptablesChainIn}
		if _, ierr := b.r.Run(ctx, tool, ins...); ierr != nil {
			return fmt.Errorf("%s %s: %w", tool, strings.Join(ins, " "), ierr)
		}
	}
	return nil
}

// scaffoldCmds returns the shell-equivalent invocations ensureScaffold performs,
// for inclusion in a Result's Commands (notably on dry-run).
func scaffoldCmds(tool string) [][]string {
	return [][]string{
		cmd(tool, []string{"-N", config.IptablesChainIn}),
		cmd(tool, []string{"-C", "INPUT", "-j", config.IptablesChainIn}),
		cmd(tool, []string{"-I", "INPUT", "-j", config.IptablesChainIn}),
	}
}

func joinAll(cmds [][]string) []string {
	out := make([]string, 0, len(cmds))
	for _, c := range cmds {
		out = append(out, strings.Join(c, " "))
	}
	return out
}

func cmd(name string, args []string) []string {
	return append([]string{name}, args...)
}

// toolFor selects iptables (IPv4) or ip6tables (IPv6) by the value's family.
func toolFor(value string) string {
	if familyOf(value) == model.FamilyIPv6 {
		return tool6
	}
	return tool4
}

// normalizeValue strips a host-prefix suffix (/32 for IPv4, /128 for IPv6) so a
// single host reads as a bare IP, mirroring what iptables itself prints.
func normalizeValue(value string) string {
	p, err := netip.ParsePrefix(value)
	if err != nil {
		return value
	}
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return value
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
