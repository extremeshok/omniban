// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package bunkerweb

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/model"
)

// ansiRE matches the SGR colour/style escape sequences bwcli decorates its
// human-readable `bans` output with; they are stripped before parsing.
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// banLineRE captures the IP, country and optional service from a ban header
// line emitted by `bwcli bans`, e.g.
//
//	🔒 203.0.113.45 [US]
//	🔒 198.51.100.7 [DE] - Service: www.example.com
//
// after ANSI codes and the leading lock icon have been stripped.
var banLineRE = regexp.MustCompile(`^(\S+)\s+\[([^\]]*)\](?:\s+-\s+Service:\s+(\S+))?`)

// remainingRE captures the human "X days Y hours …" remaining-time phrase that
// follows "for " on the clock line of a timed ban.
var remainingRE = regexp.MustCompile(`\bfor\s+(.+?)\s*$`)

// ListBans runs `bwcli bans` and parses the listed IPs, mapping remaining time
// to ExpiresAt and the reason/service to Reason/Detail. The output is the only
// machine-readable surface bwcli exposes (there is no JSON flag), so omniban
// strips the ANSI/Unicode decoration and scans the structured lines.
func (b *Backend) ListBans(ctx context.Context) ([]model.Entry, error) {
	bin := b.bin()
	if bin == "" {
		return nil, errNoBinary
	}
	res, err := b.r.Run(ctx, bin, "bans")
	if err != nil {
		return nil, fmt.Errorf("%s bans: %w", bin, err)
	}
	return parseBans(res.Stdout, time.Now()), nil
}

// parseBans extracts entries from `bwcli bans` output. now anchors the
// remaining-time arithmetic so ExpiresAt is deterministic in tests.
func parseBans(data []byte, now time.Time) []model.Entry {
	var out []model.Entry
	var cur *model.Entry
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(ansiRE.ReplaceAllString(raw, ""))
		if line == "" {
			continue
		}
		if rest, ok := afterIcon(line, "\U0001f512"); ok { // 🔒 ban header
			out = appendEntry(out, cur)
			cur = parseBanLine(rest)
			continue
		}
		if cur == nil {
			continue
		}
		if rest, ok := afterIcon(line, "⏱"); ok { // ⏱ clock / remaining line
			if exp := parseRemaining(rest, now); exp != nil {
				cur.ExpiresAt = exp
			}
			continue
		}
		if i := strings.Index(line, "Reason:"); i >= 0 {
			cur.Reason = strings.TrimSpace(line[i+len("Reason:"):])
		}
	}
	return appendEntry(out, cur)
}

// appendEntry appends a non-nil pending entry to out.
func appendEntry(out []model.Entry, cur *model.Entry) []model.Entry {
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}

// afterIcon reports whether line begins with the given leading icon (after the
// indentation already trimmed by the caller) and returns the trimmed remainder.
func afterIcon(line, icon string) (string, bool) {
	if !strings.HasPrefix(line, icon) {
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(line, icon)), true
}

// parseBanLine turns "203.0.113.45 [US] - Service: www.example.com" into an
// Entry; unparseable lines (no IP/CIDR token) yield nil.
func parseBanLine(line string) *model.Entry {
	m := banLineRE.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	value := m[1]
	fam := familyOf(value)
	if fam == "" {
		return nil
	}
	e := model.Entry{
		Value:     value,
		Family:    fam,
		Scope:     scopeOf(value),
		Kind:      model.KindBan,
		Direction: model.DirInbound,
		Origin:    model.OriginBunkerWeb,
		Backend:   string(model.OriginBunkerWeb),
		Raw:       line,
	}
	if country := strings.TrimSpace(m[2]); country != "" && !strings.EqualFold(country, "unknown") {
		e.Detail = country
	}
	if svc := strings.TrimSpace(m[3]); svc != "" {
		e.Detail = strings.TrimSpace(e.Detail + " service=" + svc)
	}
	return &e
}

// parseRemaining converts the clock line's "… for 1 day and 2 hours" suffix
// into an absolute expiry relative to now. A permanent ban (no "for" phrase)
// returns nil, leaving ExpiresAt unset.
func parseRemaining(line string, now time.Time) *time.Time {
	m := remainingRE.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	d := parseHumanDuration(m[1])
	if d <= 0 {
		return nil
	}
	exp := now.Add(d)
	return &exp
}

// parseHumanDuration parses bwcli's "1 day and 2 hours" / "30 minutes and 15
// seconds" phrasing into a Duration. Unknown units are ignored.
func parseHumanDuration(s string) time.Duration {
	fields := strings.Fields(strings.ReplaceAll(s, "and", " "))
	var total time.Duration
	for i := 0; i+1 < len(fields); i += 2 {
		n, err := strconv.Atoi(fields[i])
		if err != nil {
			continue
		}
		switch unit := strings.TrimSuffix(strings.ToLower(fields[i+1]), "s"); unit {
		case "day":
			total += time.Duration(n) * 24 * time.Hour
		case "hour":
			total += time.Duration(n) * time.Hour
		case "minute":
			total += time.Duration(n) * time.Minute
		case "second":
			total += time.Duration(n) * time.Second
		}
	}
	return total
}

// Ban adds a ban via `bwcli ban <ip> -exp <seconds> -reason <reason>`. A
// positive Duration sets the expiry in seconds; a zero Duration uses -exp 0,
// bwcli's explicit permanent ban.
func (b *Backend) Ban(ctx context.Context, req model.ActionRequest) (model.Result, error) {
	bin := b.bin()
	if bin == "" {
		return model.Result{}, errNoBinary
	}
	secs := strconv.FormatInt(int64(req.Duration.Seconds()), 10)
	args := []string{"ban", req.Value, "-exp", secs}
	if req.Reason != "" {
		args = append(args, "-reason", req.Reason)
	}
	return b.run(ctx, req.DryRun, "ban", req.Value, cmd(bin, args))
}

// Unban removes a ban globally via `bwcli unban <ip>`.
func (b *Backend) Unban(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	bin := b.bin()
	if bin == "" {
		return model.Result{}, errNoBinary
	}
	return b.run(ctx, dryRun, "unban", e.Value, cmd(bin, []string{"unban", e.Value}))
}

// run executes (or, in dry-run, only records) a single command, returning a
// Result whose Commands field holds the exact invocation.
func (b *Backend) run(ctx context.Context, dryRun bool, action, value string, c []string) (model.Result, error) {
	res := model.Result{Backend: string(model.OriginBunkerWeb), Action: action, Value: value, DryRun: dryRun}
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

// bin resolves the bwcli binary, preferring PATH then the BunkerWeb sbin path.
func (b *Backend) bin() string {
	return backend.FirstInstalled(b.r, "bwcli", "/usr/bin/bwcli", "/usr/sbin/bwcli")
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
