// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package haproxy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// errNoSocat is returned by mutations when socat cannot be located: omniban
// drives the HAProxy runtime stats socket through it.
var errNoSocat = errors.New("haproxy: socat not found — required to talk to the HAProxy runtime socket")

// ListBans reads omniban's deny map over the runtime socket and reports each
// key as an inbound IP ban. A missing socket or socat, or any socket error, is
// tolerated as an empty list (nil, nil) so listing on a host without HAProxy
// running stays clean.
func (b *Backend) ListBans(ctx context.Context) ([]model.Entry, error) {
	if backend.FirstInstalled(b.r, "socat") == "" {
		return nil, nil
	}
	res, err := b.socketCmd(ctx, "show map "+b.denyMap)
	if err != nil {
		return nil, nil
	}
	return parseShowMap(res.Out()), nil
}

// parseShowMap parses `show map <file>` output. Each entry line has three
// whitespace-separated fields — "<id-hex> <key> <value>" — where the 2nd field
// (key) is the banned IP. Blank lines and malformed lines are skipped.
func parseShowMap(out string) []model.Entry {
	var entries []model.Entry
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		key := fields[1]
		fam := familyOf(key)
		if fam == "" {
			continue
		}
		entries = append(entries, model.Entry{
			Value:     key,
			Family:    fam,
			Scope:     model.ScopeIP,
			Kind:      model.KindBan,
			Direction: model.DirInbound,
			Origin:    model.OriginHAProxy,
			Backend:   string(model.OriginHAProxy),
			NativeID:  fields[0],
			Raw:       strings.TrimSpace(line),
		})
	}
	return entries
}

// Ban adds the IP to omniban's deny map ("add map <file> <ip> ok"). The map is
// referenced by an ACL, so the block applies with no reload. ("set map" only
// updates an existing key; "add map" inserts a new one.)
func (b *Backend) Ban(ctx context.Context, req model.ActionRequest) (model.Result, error) {
	return b.mutate(ctx, req.DryRun, "ban", req.Value, "add map "+b.denyMap+" "+req.Value+" ok")
}

// Unban removes the IP from omniban's deny map ("del map <file> <ip>").
func (b *Backend) Unban(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	return b.mutate(ctx, dryRun, "unban", e.Value, "del map "+b.denyMap+" "+e.Value)
}

// mutate records and (unless dry-run) sends a single map command over the
// runtime socket. Result.Commands holds the socat invocation followed by the
// map command actually written to the socket.
func (b *Backend) mutate(ctx context.Context, dryRun bool, action, value, cmd string) (model.Result, error) {
	res := model.Result{Backend: string(model.OriginHAProxy), Action: action, Value: value, DryRun: dryRun}
	socat := backend.FirstInstalled(b.r, "socat")
	if socat == "" {
		return res, errNoSocat
	}
	res.Commands = []string{
		strings.Join(socatArgv(socat, b.socket), " "),
		cmd,
	}
	if dryRun {
		res.Message = "dry-run: not executed"
		return res, nil
	}
	if _, err := b.socketCmd(ctx, cmd); err != nil {
		return res, fmt.Errorf("%s: %w", cmd, err)
	}
	res.Changed = true
	return res, nil
}

// socketCmd writes "<cmd>\n" to the HAProxy runtime socket via socat and
// returns the captured output.
func (b *Backend) socketCmd(ctx context.Context, cmd string) (exec.Result, error) {
	return b.r.RunInput(ctx, []byte(cmd+"\n"), "socat", "-", "UNIX-CONNECT:"+b.socket)
}

// socatArgv is the exact argv used to talk to the runtime socket; recorded in
// Result.Commands so the operator sees the precise invocation.
func socatArgv(socat, socket string) []string {
	return []string{socat, "-", "UNIX-CONNECT:" + socket}
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
