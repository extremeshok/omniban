// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package manager

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/extremeshok/omniban/internal/audit"
	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/model"
	"github.com/extremeshok/omniban/internal/resolve"
	"github.com/extremeshok/omniban/internal/safety"
)

// ListAll gathers entries of the given kind from every installed backend,
// deduplicated and attributed. Per-backend failures become warnings.
func (m *Manager) ListAll(ctx context.Context, kind model.Kind) ([]model.Entry, []string, error) {
	statuses := m.Detect(ctx)
	var all []model.Entry
	var warns []string
	for i, b := range m.backends {
		if !statuses[i].Detection.Installed {
			continue
		}
		var (
			entries []model.Entry
			err     error
		)
		if kind == model.KindAllow {
			entries, err = b.ListAllows(ctx)
		} else {
			entries, err = b.ListBans(ctx)
		}
		if err != nil {
			if errors.Is(err, backend.ErrNotImplemented) {
				continue
			}
			warns = append(warns, fmt.Sprintf("%s: %v", b.Name(), err))
			continue
		}
		all = append(all, entries...)
	}
	return dedup(all), warns, nil
}

// Search returns the entries of the given kind that match query. When the query
// is a hostname it is also resolved to addresses, each matched in turn.
func (m *Manager) Search(ctx context.Context, query string, contains bool, kind model.Kind) ([]model.Entry, []string, error) {
	all, warns, err := m.ListAll(ctx, kind)
	if err != nil {
		return nil, warns, err
	}
	matchers := []resolve.Matcher{resolve.NewMatcher(query, contains)}
	if hostnameOnly(query) {
		if addrs, rerr := m.resolver.Hostname(ctx, query); rerr == nil {
			for _, a := range addrs {
				matchers = append(matchers, resolve.NewMatcher(a.String(), contains))
			}
		}
	}
	var out []model.Entry
	for _, e := range all {
		for _, mt := range matchers {
			if mt.Matches(e) {
				out = append(out, e)
				break
			}
		}
	}
	return out, warns, nil
}

// Ban routes a ban to the target backend (explicit --via, else the /etc/hosts
// sinkhole for domains, else the manual firewall target), enforcing the lockout
// guard unless force is set, and recording audit + undo.
func (m *Manager) Ban(ctx context.Context, req model.ActionRequest, force bool) (model.Result, error) {
	req.Kind = model.KindBan
	if req.Scope == "" {
		req.Scope = scopeOf(req.Value)
	}
	if req.Direction == "" {
		req.Direction = directionFor(req.Scope)
	}
	if !force {
		if protected, reason := m.guard.IsProtected(req.Value); protected {
			return model.Result{}, fmt.Errorf("refusing to ban: %s", reason)
		}
	}
	b, err := m.targetFor(ctx, req)
	if err != nil {
		return model.Result{}, err
	}
	res, err := b.Ban(ctx, req)
	m.record(res, req.Reason, err)
	if err == nil && res.Changed {
		_ = m.journal.Push(undoFor("unban", res.Backend, req.Value, req.Scope, req.Kind, req.Direction))
	}
	return res, err
}

// Allow routes an allowlist addition to the target backend.
func (m *Manager) Allow(ctx context.Context, req model.ActionRequest) (model.Result, error) {
	req.Kind = model.KindAllow
	if req.Scope == "" {
		req.Scope = scopeOf(req.Value)
	}
	if req.Direction == "" {
		req.Direction = model.DirInbound
	}
	b, err := m.targetFor(ctx, req)
	if err != nil {
		return model.Result{}, err
	}
	res, err := b.Allow(ctx, req)
	m.record(res, req.Reason, err)
	if err == nil && res.Changed {
		_ = m.journal.Push(undoFor("unallow", res.Backend, req.Value, req.Scope, req.Kind, req.Direction))
	}
	return res, err
}

// Unban removes a ban. With via set, it targets that backend; otherwise it
// unbans every backend currently reporting the value (and, with allBackends,
// the enforcement-layer copies in AlsoSeenIn too).
func (m *Manager) Unban(ctx context.Context, value, via string, allBackends, dryRun bool) ([]model.Result, error) {
	scope := scopeOf(value)
	if via != "" {
		b, ok := m.byName(via)
		if !ok {
			return nil, fmt.Errorf("unknown backend %q", via)
		}
		res, err := b.Unban(ctx, model.Entry{Value: value, Scope: scope}, dryRun)
		m.record(res, "", err)
		if err == nil && res.Changed {
			_ = m.journal.Push(undoFor("ban", res.Backend, value, scope, model.KindBan, directionFor(scope)))
		}
		return []model.Result{res}, err
	}

	entries, _, err := m.ListAll(ctx, model.KindBan)
	if err != nil {
		return nil, err
	}
	var targets []model.Entry
	for _, e := range entries {
		if strings.EqualFold(e.Value, value) {
			targets = append(targets, e)
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("%s is not banned in any detected backend (use --via to target one)", value)
	}

	var results []model.Result
	for _, e := range targets {
		b, ok := m.byName(e.Backend)
		if !ok {
			continue
		}
		res, uerr := b.Unban(ctx, e, dryRun)
		m.record(res, "", uerr)
		results = append(results, res)
		if uerr != nil {
			return results, uerr
		}
		if allBackends {
			for _, name := range e.AlsoSeenIn {
				if bb, ok := m.byName(name); ok {
					rr, _ := bb.Unban(ctx, model.Entry{Value: e.Value, Scope: e.Scope}, dryRun)
					results = append(results, rr)
				}
			}
		}
	}
	return results, nil
}

// Unallow removes an allowlist entry, targeting via or every backend reporting it.
func (m *Manager) Unallow(ctx context.Context, value, via string, dryRun bool) ([]model.Result, error) {
	scope := scopeOf(value)
	if via != "" {
		b, ok := m.byName(via)
		if !ok {
			return nil, fmt.Errorf("unknown backend %q", via)
		}
		res, err := b.RemoveAllow(ctx, model.Entry{Value: value, Scope: scope}, dryRun)
		m.record(res, "", err)
		return []model.Result{res}, err
	}
	entries, _, err := m.ListAll(ctx, model.KindAllow)
	if err != nil {
		return nil, err
	}
	var results []model.Result
	for _, e := range entries {
		if !strings.EqualFold(e.Value, value) {
			continue
		}
		b, ok := m.byName(e.Backend)
		if !ok {
			continue
		}
		res, rerr := b.RemoveAllow(ctx, e, dryRun)
		m.record(res, "", rerr)
		results = append(results, res)
		if rerr != nil {
			return results, rerr
		}
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("%s is not allowlisted in any detected backend (use --via to target one)", value)
	}
	return results, nil
}

// Undo replays the inverse of the most recent mutating action.
func (m *Manager) Undo(ctx context.Context, dryRun bool) (model.Result, error) {
	rec, ok, err := m.journal.Pop()
	if err != nil {
		return model.Result{}, err
	}
	if !ok {
		return model.Result{}, errors.New("nothing to undo")
	}
	b, found := m.byName(rec.Backend)
	if !found {
		return model.Result{}, fmt.Errorf("undo target backend %q is not available", rec.Backend)
	}
	entry := model.Entry{Value: rec.Value, Scope: model.Scope(rec.Scope)}
	req := model.ActionRequest{Value: rec.Value, Scope: model.Scope(rec.Scope), Backend: rec.Backend, DryRun: dryRun}
	switch rec.InverseOp {
	case "unban":
		return b.Unban(ctx, entry, dryRun)
	case "ban":
		req.Kind = model.KindBan
		return b.Ban(ctx, req)
	case "unallow":
		return b.RemoveAllow(ctx, entry, dryRun)
	case "allow":
		req.Kind = model.KindAllow
		return b.Allow(ctx, req)
	default:
		return model.Result{}, fmt.Errorf("unknown undo op %q", rec.InverseOp)
	}
}

// applier is implemented by backends that persist state for boot replay.
type applier interface {
	Apply(ctx context.Context) error
}

// ApplyPersisted replays every backend's persisted state (e.g. blackhole
// routes). Used by `omniban apply-routes` at boot via the systemd oneshot.
func (m *Manager) ApplyPersisted(ctx context.Context) error {
	var firstErr error
	for _, b := range m.backends {
		ap, ok := b.(applier)
		if !ok {
			continue
		}
		if err := ap.Apply(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// targetFor selects the backend for a mutation: explicit --via, else the hosts
// sinkhole for domains, else the manual firewall target for inbound IP bans.
func (m *Manager) targetFor(ctx context.Context, req model.ActionRequest) (backend.Backend, error) {
	if req.Backend != "" {
		b, ok := m.byName(req.Backend)
		if !ok {
			return nil, fmt.Errorf("unknown backend %q", req.Backend)
		}
		return b, nil
	}
	if req.Scope == model.ScopeDomain {
		if b, ok := m.byName(string(model.OriginHosts)); ok {
			return b, nil
		}
		return nil, errors.New("no /etc/hosts backend available")
	}
	target := m.ManualTarget(m.Detect(ctx))
	if target == "" {
		return nil, errors.New("no writable firewall backend is active; specify --via")
	}
	b, ok := m.byName(target)
	if !ok {
		return nil, fmt.Errorf("manual target %q is unavailable", target)
	}
	return b, nil
}

func (m *Manager) record(res model.Result, reason string, opErr error) {
	result := "ok"
	if opErr != nil {
		result = "error: " + opErr.Error()
	} else if res.DryRun {
		result = "dry-run"
	}
	_ = m.audit.Write(audit.Record{
		Action:   res.Action,
		Backend:  res.Backend,
		Value:    res.Value,
		Reason:   reason,
		DryRun:   res.DryRun,
		Result:   result,
		NativeID: "",
	})
}

func undoFor(op, backendName, value string, scope model.Scope, kind model.Kind, dir model.Direction) safety.UndoRecord {
	return safety.UndoRecord{
		InverseOp: op,
		Backend:   backendName,
		Value:     value,
		Scope:     string(scope),
		Kind:      string(kind),
		Direction: string(dir),
	}
}

// dedup collapses entries sharing (family, value, kind, direction) into one row
// owned by the highest-precedence backend (IDS > firewall > routing > DNS),
// listing the rest in AlsoSeenIn.
func dedup(entries []model.Entry) []model.Entry {
	type key struct {
		fam  model.Family
		val  string
		kind model.Kind
		dir  model.Direction
	}
	groups := map[key][]model.Entry{}
	var order []key
	for _, e := range entries {
		k := key{e.Family, strings.ToLower(e.Value), e.Kind, e.Direction}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], e)
	}
	out := make([]model.Entry, 0, len(order))
	for _, k := range order {
		g := groups[k]
		pi := 0
		for i := 1; i < len(g); i++ {
			if rankOf(g[i].Origin) < rankOf(g[pi].Origin) {
				pi = i
			}
		}
		primary := g[pi]
		alsoSet := map[string]bool{}
		for i, e := range g {
			if i == pi || e.Backend == primary.Backend {
				continue
			}
			alsoSet[e.Backend] = true
		}
		var also []string
		for b := range alsoSet {
			also = append(also, b)
		}
		sort.Strings(also)
		primary.AlsoSeenIn = also
		out = append(out, primary)
	}
	return out
}

// rankOf maps an origin to its attribution precedence (lower wins).
func rankOf(o model.Origin) int {
	switch o {
	case model.OriginFail2ban, model.OriginCrowdSec, model.OriginSSHGuard,
		model.OriginDenyHosts, model.OriginCSF, model.OriginAPF, model.OriginBFD,
		model.OriginSuricata, model.OriginWazuh:
		return 0 // IDS / detection owners
	case model.OriginBlackhole:
		return 2 // routing
	case model.OriginHosts:
		return 3 // DNS
	default:
		return 1 // firewall / manual
	}
}

func scopeOf(value string) model.Scope {
	if _, err := netip.ParseAddr(value); err == nil {
		return model.ScopeIP
	}
	if _, err := netip.ParsePrefix(value); err == nil {
		return model.ScopeRange
	}
	return model.ScopeDomain
}

func directionFor(scope model.Scope) model.Direction {
	if scope == model.ScopeDomain {
		return model.DirOutbound
	}
	return model.DirInbound
}

func hostnameOnly(q string) bool {
	q = strings.TrimSpace(q)
	if q == "" || strings.ContainsAny(q, "*?/") {
		return false
	}
	if _, err := netip.ParseAddr(q); err == nil {
		return false
	}
	return strings.Contains(q, ".")
}
