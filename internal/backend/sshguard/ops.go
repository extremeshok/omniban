// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package sshguard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/extremeshok/omniban/internal/model"
)

const backupSuffix = ".omniban.bak"

// ListAllows reads the sshguard whitelist file and reports each non-comment
// entry as an allowlist Entry. A missing file yields no entries (not an error).
func (b *Backend) ListAllows(_ context.Context) ([]model.Entry, error) {
	data, err := os.ReadFile(b.whitelist)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", b.whitelist, err)
	}
	var out []model.Entry
	for _, line := range strings.Split(string(data), "\n") {
		v := strings.TrimSpace(line)
		if v == "" || strings.HasPrefix(v, "#") {
			continue
		}
		out = append(out, model.Entry{
			Value:     v,
			Family:    familyOf(v),
			Scope:     scopeOf(v),
			Kind:      model.KindAllow,
			Direction: model.DirInbound,
			Origin:    model.OriginSSHGuard,
			Backend:   string(model.OriginSSHGuard),
			Raw:       line,
		})
	}
	return out, nil
}

// Allow appends value to the sshguard whitelist file. It is idempotent (an
// existing entry is a no-op), backs the file up before the first edit, and
// honours dry-run by only recording the intended edit.
func (b *Backend) Allow(_ context.Context, req model.ActionRequest) (model.Result, error) {
	res := model.Result{
		Backend:  string(model.OriginSSHGuard),
		Action:   "allow",
		Value:    req.Value,
		DryRun:   req.DryRun,
		Commands: []string{fmt.Sprintf("append %q to %s", req.Value, b.whitelist)},
	}
	if req.DryRun {
		res.Message = "dry-run: not executed"
		return res, nil
	}

	lines, err := readLines(b.whitelist)
	if err != nil {
		return res, err
	}
	if containsValue(lines, req.Value) {
		res.Message = "already present"
		return res, nil
	}
	if err := backup(b.whitelist); err != nil {
		return res, err
	}
	lines = append(lines, req.Value)
	if err := writeLines(b.whitelist, lines); err != nil {
		return res, err
	}
	res.Changed = true
	return res, nil
}

// RemoveAllow deletes value from the sshguard whitelist file. It backs the file
// up before editing and honours dry-run by only recording the intended edit.
func (b *Backend) RemoveAllow(_ context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	res := model.Result{
		Backend:  string(model.OriginSSHGuard),
		Action:   "unallow",
		Value:    e.Value,
		DryRun:   dryRun,
		Commands: []string{fmt.Sprintf("remove %q from %s", e.Value, b.whitelist)},
	}
	if dryRun {
		res.Message = "dry-run: not executed"
		return res, nil
	}

	lines, err := readLines(b.whitelist)
	if err != nil {
		if os.IsNotExist(err) {
			res.Message = "not present"
			return res, nil
		}
		return res, err
	}
	kept := make([]string, 0, len(lines))
	removed := false
	for _, line := range lines {
		if strings.TrimSpace(line) == e.Value {
			removed = true
			continue
		}
		kept = append(kept, line)
	}
	if !removed {
		res.Message = "not present"
		return res, nil
	}
	if err := backup(b.whitelist); err != nil {
		return res, err
	}
	if err := writeLines(b.whitelist, kept); err != nil {
		return res, err
	}
	res.Changed = true
	return res, nil
}

// ListBans best-effort reports the IPs sshguard is currently blocking via its
// nftables sets. When nft is absent or no sshguard set exists, it returns no
// entries rather than an error.
func (b *Backend) ListBans(ctx context.Context) ([]model.Entry, error) {
	res, err := b.r.Run(ctx, "nft", "-j", "list", "ruleset")
	if err != nil {
		return nil, nil
	}
	return parseRuleset(res.Stdout)
}

// Unban best-effort removes value from sshguard's nftables attackers set. The
// family element (ip/ip6) is derived from the value.
func (b *Backend) Unban(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	fam := nftFamily(e.Value)
	args := []string{"delete", "element", fam, "sshguard", "attackers", "{", e.Value, "}"}
	res := model.Result{
		Backend:  string(model.OriginSSHGuard),
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

// nftRuleset mirrors the top-level shape of `nft -j list ruleset`.
type nftRuleset struct {
	Nftables []nftObject `json:"nftables"`
}

// nftObject is one entry of the nftables array; only the set field is parsed,
// the rest (table, rule, chain, metainfo) are ignored.
type nftObject struct {
	Set *nftSet `json:"set"`
}

// nftSet is a named set; sshguard stores blocked addresses in set "attackers".
type nftSet struct {
	Family string            `json:"family"`
	Name   string            `json:"name"`
	Table  string            `json:"table"`
	Elem   []json.RawMessage `json:"elem"`
}

// nftPrefix is the CIDR element form: {"prefix":{"addr":"10.0.0.0","len":24}}.
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
		if s == nil || !strings.Contains(s.Table, "sshguard") {
			continue
		}
		for _, raw := range s.Elem {
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
				Origin:    model.OriginSSHGuard,
				Backend:   string(model.OriginSSHGuard),
			})
		}
	}
	return out, nil
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

// readLines returns the file split into lines, with no trailing empty element.
func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := strings.TrimRight(string(data), "\n")
	if content == "" {
		return nil, nil
	}
	return strings.Split(content, "\n"), nil
}

// writeLines writes lines back to path with a trailing newline, preserving the
// file mode when it already exists.
func writeLines(path string, lines []string) error {
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// backup copies path to path+backupSuffix before the first edit.
func backup(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := os.WriteFile(path+backupSuffix, data, 0o644); err != nil {
		return fmt.Errorf("backup %s: %w", path, err)
	}
	return nil
}

func containsValue(lines []string, value string) bool {
	for _, line := range lines {
		if strings.TrimSpace(line) == value {
			return true
		}
	}
	return false
}

// nftFamily returns the nftables family keyword for value: "ip6" for IPv6,
// "ip" otherwise (IPv4 or anything else).
func nftFamily(value string) string {
	if f := familyOf(value); f == model.FamilyIPv6 {
		return "ip6"
	}
	return "ip"
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
