// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package firewalld

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/extremeshok/omniban/internal/model"
)

// sourceAddrRe extracts the source address value from a rich rule line such as
//
//	rule family="ipv4" source address="1.2.3.4" drop
var sourceAddrRe = regexp.MustCompile(`source\s+address="([^"]+)"`)

// ListBans returns omniban's drop/reject rich rules as inbound bans.
func (b *Backend) ListBans(ctx context.Context) ([]model.Entry, error) {
	return b.listRules(ctx, model.KindBan)
}

// ListAllows returns omniban's accept rich rules as inbound allows.
func (b *Backend) ListAllows(ctx context.Context) ([]model.Entry, error) {
	return b.listRules(ctx, model.KindAllow)
}

// listRules runs `firewall-cmd --list-rich-rules` and returns the rules whose
// action matches the requested kind: drop/reject -> bans, accept -> allows.
// Only rules carrying a source address are considered.
func (b *Backend) listRules(ctx context.Context, kind model.Kind) ([]model.Entry, error) {
	res, err := b.r.Run(ctx, "firewall-cmd", "--list-rich-rules")
	if err != nil {
		return nil, fmt.Errorf("firewall-cmd --list-rich-rules: %w", err)
	}
	var out []model.Entry
	sc := bufio.NewScanner(strings.NewReader(res.Out()))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		m := sourceAddrRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if ruleKind(line) != kind {
			continue
		}
		value := m[1]
		fam := familyOf(value)
		if fam == "" {
			continue
		}
		out = append(out, model.Entry{
			Value:     value,
			Family:    fam,
			Scope:     scopeOf(value),
			Kind:      kind,
			Direction: model.DirInbound,
			Origin:    model.OriginFirewalld,
			Backend:   string(model.OriginFirewalld),
			Raw:       line,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan rich rules: %w", err)
	}
	return out, nil
}

// Ban adds a permanent drop rich rule for the value, then reloads to apply it.
func (b *Backend) Ban(ctx context.Context, req model.ActionRequest) (model.Result, error) {
	return b.mutate(ctx, req.DryRun, "ban", req.Value, richRule(req.Value, "drop"))
}

// Unban removes the permanent drop rich rule for the value, then reloads.
func (b *Backend) Unban(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	return b.mutateRemove(ctx, dryRun, "unban", e.Value, richRule(e.Value, "drop"))
}

// Allow adds a permanent accept rich rule for the value, then reloads.
func (b *Backend) Allow(ctx context.Context, req model.ActionRequest) (model.Result, error) {
	return b.mutate(ctx, req.DryRun, "allow", req.Value, richRule(req.Value, "accept"))
}

// RemoveAllow removes the permanent accept rich rule for the value, then reloads.
func (b *Backend) RemoveAllow(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	return b.mutateRemove(ctx, dryRun, "unallow", e.Value, richRule(e.Value, "accept"))
}

// Reload applies pending permanent changes (firewall-cmd --reload).
func (b *Backend) Reload(ctx context.Context) error {
	if _, err := b.r.Run(ctx, "firewall-cmd", "--reload"); err != nil {
		return fmt.Errorf("firewall-cmd --reload: %w", err)
	}
	return nil
}

// mutate adds a permanent rich rule then reloads. The rule text is passed as a
// single argv element (--add-rich-rule=<rule>), never split into words.
func (b *Backend) mutate(ctx context.Context, dryRun bool, action, value, rule string) (model.Result, error) {
	add := []string{"firewall-cmd", "--permanent", "--add-rich-rule=" + rule}
	reload := []string{"firewall-cmd", "--reload"}
	return b.run(ctx, dryRun, action, value, [][]string{add, reload})
}

// mutateRemove removes a permanent rich rule then reloads.
func (b *Backend) mutateRemove(ctx context.Context, dryRun bool, action, value, rule string) (model.Result, error) {
	remove := []string{"firewall-cmd", "--permanent", "--remove-rich-rule=" + rule}
	reload := []string{"firewall-cmd", "--reload"}
	return b.run(ctx, dryRun, action, value, [][]string{remove, reload})
}

// run executes (or, in dry-run, only records) the supplied commands, returning a
// Result whose Commands field holds the exact invocations.
func (b *Backend) run(ctx context.Context, dryRun bool, action, value string, cmds [][]string) (model.Result, error) {
	res := model.Result{Backend: string(model.OriginFirewalld), Action: action, Value: value, DryRun: dryRun}
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

// richRule builds a source-address rich rule string with the given action.
func richRule(value, action string) string {
	return fmt.Sprintf("rule family=%q source address=%q %s", famName(value), value, action)
}

// ruleKind classifies a rich rule line by its action verb.
func ruleKind(line string) model.Kind {
	switch {
	case strings.Contains(line, " accept"):
		return model.KindAllow
	case strings.Contains(line, " drop"), strings.Contains(line, " reject"):
		return model.KindBan
	default:
		return ""
	}
}

// famName returns the firewalld rich-rule family token (ipv4/ipv6) for value,
// defaulting to ipv4 for unparseable input.
func famName(value string) string {
	if familyOf(value) == model.FamilyIPv6 {
		return "ipv6"
	}
	return "ipv4"
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
