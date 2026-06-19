// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package nftables

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/extremeshok/omniban/internal/config"
	"github.com/extremeshok/omniban/internal/model"
)

// tableFamily is the nftables family for omniban's owned table.
const tableFamily = "inet"

// persistPath is where Reload best-effort snapshots the owned table for the
// boot-replay command (added later) to apply.
var persistPath = "/etc/omniban/nftables.nft"

// ListBans reads omniban's own deny4/deny6 sets from the live ruleset and
// reports each element as an inbound ban. A missing table (or absent nft)
// yields no entries rather than an error.
func (b *Backend) ListBans(ctx context.Context) ([]model.Entry, error) {
	res, err := b.r.Run(ctx, "nft", "-j", "list", "ruleset")
	if err != nil {
		return nil, nil
	}
	return parseRuleset(res.Stdout)
}

// Ban ensures the owned scaffold exists, then adds the value to the
// family-appropriate deny set (deny4 for IPv4, deny6 for IPv6).
func (b *Backend) Ban(ctx context.Context, req model.ActionRequest) (model.Result, error) {
	set := setFor(req.Value)
	args := []string{"add", "element", tableFamily, config.NftTable, set, "{", req.Value, "}"}
	res := model.Result{
		Backend:  b.Name(),
		Action:   "ban",
		Value:    req.Value,
		DryRun:   req.DryRun,
		Commands: []string{"nft " + strings.Join(args, " ")},
	}
	if req.DryRun {
		res.Message = "dry-run: not executed"
		return res, nil
	}
	if err := b.ensureScaffold(ctx); err != nil {
		return res, err
	}
	if _, err := b.r.Run(ctx, "nft", args...); err != nil {
		return res, fmt.Errorf("nft %s: %w", strings.Join(args, " "), err)
	}
	res.Changed = true
	return res, nil
}

// Unban removes the value from the family-appropriate owned deny set.
func (b *Backend) Unban(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	set := setFor(e.Value)
	args := []string{"delete", "element", tableFamily, config.NftTable, set, "{", e.Value, "}"}
	res := model.Result{
		Backend:  b.Name(),
		Action:   "unban",
		Value:    e.Value,
		DryRun:   dryRun,
		Commands: []string{"nft " + strings.Join(args, " ")},
	}
	if dryRun {
		res.Message = "dry-run: not executed"
		return res, nil
	}
	if _, err := b.r.Run(ctx, "nft", args...); err != nil {
		return res, fmt.Errorf("nft %s: %w", strings.Join(args, " "), err)
	}
	res.Changed = true
	return res, nil
}

// Reload best-effort snapshots the owned table to persistPath so the boot
// replay can restore it. Any failure (no table, unwritable dir) is swallowed —
// reload must never break the calling flow.
func (b *Backend) Reload(ctx context.Context) error {
	res, err := b.r.Run(ctx, "nft", "list", "table", tableFamily, config.NftTable)
	if err != nil {
		return nil
	}
	if mkErr := os.MkdirAll(filepath.Dir(persistPath), 0o755); mkErr != nil {
		return nil
	}
	_ = os.WriteFile(persistPath, []byte(res.Out()+"\n"), 0o644)
	return nil
}

// ensureScaffold idempotently creates omniban's owned table, deny sets, input
// chain, and the referencing drop rules. It probes for the table first and only
// creates the objects when absent, so a second call is a no-op. omniban only
// ever touches its own "inet omniban" table — never a foreign one.
func (b *Backend) ensureScaffold(ctx context.Context) error {
	if _, err := b.r.Run(ctx, "nft", "list", "table", tableFamily, config.NftTable); err == nil {
		return nil // already present
	}
	for _, args := range scaffoldCmds() {
		if _, err := b.r.Run(ctx, "nft", args...); err != nil {
			return fmt.Errorf("nft %s: %w", strings.Join(args, " "), err)
		}
	}
	return nil
}

// scaffoldCmds returns, in dependency order, the nft argv slices that build the
// owned table. The brace block of a set definition is a single argv element to
// match how nft tokenizes it when not invoked through a shell.
func scaffoldCmds() [][]string {
	return [][]string{
		{"add", "table", tableFamily, config.NftTable},
		{"add", "set", tableFamily, config.NftTable, config.NftSet4, "{ type ipv4_addr ; flags interval ; }"},
		{"add", "set", tableFamily, config.NftTable, config.NftSet6, "{ type ipv6_addr ; flags interval ; }"},
		{"add", "chain", tableFamily, config.NftTable, "input", "{ type filter hook input priority 0 ; policy accept ; }"},
		{"add", "rule", tableFamily, config.NftTable, "input", "ip", "saddr", "@" + config.NftSet4, "drop"},
		{"add", "rule", tableFamily, config.NftTable, "input", "ip6", "saddr", "@" + config.NftSet6, "drop"},
	}
}

// setFor returns the owned set name for a value's family: deny6 for IPv6,
// deny4 otherwise (IPv4 or a non-IP value defaults to the v4 set).
func setFor(value string) string {
	if familyOf(value) == model.FamilyIPv6 {
		return config.NftSet6
	}
	return config.NftSet4
}

// nftRuleset mirrors the top-level shape of `nft -j list ruleset`.
type nftRuleset struct {
	Nftables []nftObject `json:"nftables"`
}

// nftObject is one entry of the nftables array; only the set field is parsed,
// the rest (table, rule, chain, metainfo) are ignored.
type nftObject struct {
	Set *nftSet `json:"set"`
}

// nftSet is a named set. omniban stores bans in its own deny4/deny6 sets; some
// nft versions key the members "elem", others "elements", so both are read.
type nftSet struct {
	Family   string            `json:"family"`
	Name     string            `json:"name"`
	Table    string            `json:"table"`
	Elem     []json.RawMessage `json:"elem"`
	Elements []json.RawMessage `json:"elements"`
}

// nftPrefix is the CIDR element form: {"prefix":{"addr":"10.0.0.0","len":8}}.
type nftPrefix struct {
	Prefix struct {
		Addr string `json:"addr"`
		Len  int    `json:"len"`
	} `json:"prefix"`
}

func parseRuleset(data []byte) ([]model.Entry, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, nil
	}
	var rs nftRuleset
	if err := json.Unmarshal([]byte(trimmed), &rs); err != nil {
		return nil, fmt.Errorf("parse nft ruleset json: %w", err)
	}
	var out []model.Entry
	for _, obj := range rs.Nftables {
		s := obj.Set
		if s == nil || !isOwnedSet(s) {
			continue
		}
		members := s.Elem
		if len(members) == 0 {
			members = s.Elements
		}
		for _, raw := range members {
			value, ok := decodeElem(raw)
			if !ok {
				continue
			}
			out = append(out, model.Entry{
				Value:     value,
				Family:    familyOf(value),
				Scope:     scopeOf(value),
				Kind:      model.KindBan,
				Direction: model.DirInbound,
				Origin:    model.OriginNftables,
				Backend:   string(model.OriginNftables),
			})
		}
	}
	return out, nil
}

// isOwnedSet reports whether a set belongs to omniban's table and is one of its
// deny sets — never a foreign table's set.
func isOwnedSet(s *nftSet) bool {
	if s.Table != config.NftTable {
		return false
	}
	return s.Name == config.NftSet4 || s.Name == config.NftSet6
}

// decodeElem turns one nft set element into a value string. Bare addresses are
// JSON strings; CIDRs are {"prefix":{...}} objects.
func decodeElem(raw json.RawMessage) (string, bool) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, true
	}
	var p nftPrefix
	if err := json.Unmarshal(raw, &p); err == nil && p.Prefix.Addr != "" {
		return fmt.Sprintf("%s/%d", p.Prefix.Addr, p.Prefix.Len), true
	}
	return "", false
}

// scopeOf classifies a value as a CIDR range or a single IP.
func scopeOf(value string) model.Scope {
	if strings.Contains(value, "/") {
		return model.ScopeRange
	}
	return model.ScopeIP
}

// familyOf returns the address family of an IP or CIDR value, or "" for a
// hostname or unparseable value.
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
