// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package fail2ban

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/extremeshok/omniban/internal/model"
)

// ListBans returns the IPs fail2ban currently has banned, one Entry per
// (jail, ip) pair. It enumerates jails from `fail2ban-client status`, then
// reads each jail's banned IP list from `fail2ban-client status <jail>`.
func (b *Backend) ListBans(ctx context.Context) ([]model.Entry, error) {
	res, err := b.r.Run(ctx, "fail2ban-client", "status")
	if err != nil {
		return nil, fmt.Errorf("fail2ban-client status: %w", err)
	}
	jails := parseJailList(res.Out())

	var out []model.Entry
	for _, jail := range jails {
		jres, jerr := b.r.Run(ctx, "fail2ban-client", "status", jail)
		if jerr != nil {
			return nil, fmt.Errorf("fail2ban-client status %s: %w", jail, jerr)
		}
		for _, ip := range parseBannedIPs(jres.Out()) {
			out = append(out, model.Entry{
				Value:     ip,
				Family:    familyOf(ip),
				Scope:     model.ScopeIP,
				Kind:      model.KindBan,
				Direction: model.DirInbound,
				Origin:    model.OriginFail2ban,
				Backend:   string(model.OriginFail2ban),
				Detail:    jail,
			})
		}
	}
	return out, nil
}

// Unban removes a banned IP. With a jail (Entry.Detail) it targets that jail;
// without one it uses the all-jails form so the IP is cleared everywhere.
func (b *Backend) Unban(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	var c []string
	if e.Detail != "" {
		c = cmd("fail2ban-client", []string{"set", e.Detail, "unbanip", e.Value})
	} else {
		c = cmd("fail2ban-client", []string{"unban", e.Value})
	}
	return b.run(ctx, dryRun, "unban", e.Value, [][]string{c})
}

// run executes (or, in dry-run, only records) one or more commands, returning a
// Result whose Commands field holds the exact invocations.
func (b *Backend) run(ctx context.Context, dryRun bool, action, value string, cmds [][]string) (model.Result, error) {
	res := model.Result{Backend: string(model.OriginFail2ban), Action: action, Value: value, DryRun: dryRun}
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

func cmd(name string, args []string) []string {
	return append([]string{name}, args...)
}

// parseJailList extracts the jail names from `fail2ban-client status` output.
// The relevant line looks like "`- Jail list:\tsshd, nginx-http-auth"; jails
// are comma-separated after the first colon.
func parseJailList(out string) []string {
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "Jail list:") {
			continue
		}
		_, rest, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		var jails []string
		for _, j := range strings.Split(rest, ",") {
			if t := strings.TrimSpace(j); t != "" {
				jails = append(jails, t)
			}
		}
		return jails
	}
	return nil
}

// parseBannedIPs extracts the banned IPs from `fail2ban-client status <jail>`
// output. The relevant line looks like "   `- Banned IP list:\t1.2.3.4 5.6.7.8";
// IPs are whitespace-separated after the first colon and may be empty.
func parseBannedIPs(out string) []string {
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "Banned IP list:") {
			continue
		}
		_, rest, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		return strings.Fields(rest)
	}
	return nil
}

func familyOf(value string) model.Family {
	if addr, err := netip.ParseAddr(value); err == nil {
		if addr.Is6() && !addr.Is4In6() {
			return model.FamilyIPv6
		}
		return model.FamilyIPv4
	}
	return ""
}
