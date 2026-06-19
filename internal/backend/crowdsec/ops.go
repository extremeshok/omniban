// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package crowdsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/extremeshok/omniban/internal/model"
)

// allowlistName is the dedicated CrowdSec allowlist omniban manages (1.6.6+).
const allowlistName = "omniban"

// cscliDecision mirrors a single decision in `cscli decisions list -o json`.
type cscliDecision struct {
	ID       int64  `json:"id"`
	Origin   string `json:"origin"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Duration string `json:"duration"`
	Scenario string `json:"scenario"`
}

// cscliAlert is the top-level element of `cscli decisions list -o json`: modern
// cscli (1.7.x) wraps decisions inside alert objects (the nested "decisions"
// array). The embedded cscliDecision also captures the older flat schema, where
// each top-level element *is* a decision.
type cscliAlert struct {
	Decisions []cscliDecision `json:"decisions"`
	cscliDecision
}

// ListBans returns active CrowdSec ban decisions.
func (b *Backend) ListBans(ctx context.Context) ([]model.Entry, error) {
	res, err := b.r.Run(ctx, "cscli", "decisions", "list", "-o", "json")
	if err != nil {
		return nil, fmt.Errorf("cscli decisions list: %w", err)
	}
	return parseDecisions(res.Stdout, time.Now())
}

func parseDecisions(data []byte, now time.Time) ([]model.Entry, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" || trimmed == "[]" {
		return nil, nil
	}
	var alerts []cscliAlert
	if err := json.Unmarshal([]byte(trimmed), &alerts); err != nil {
		return nil, fmt.Errorf("parse cscli decisions json: %w", err)
	}
	// Flatten: modern cscli nests decisions inside alerts; the older flat schema
	// puts the decision fields on the top-level element itself.
	var ds []cscliDecision
	for _, a := range alerts {
		if len(a.Decisions) > 0 {
			ds = append(ds, a.Decisions...)
		} else if a.Value != "" {
			ds = append(ds, a.cscliDecision)
		}
	}
	out := make([]model.Entry, 0, len(ds))
	for _, d := range ds {
		if d.Type != "" && d.Type != "ban" {
			continue
		}
		e := model.Entry{
			Value:     d.Value,
			Family:    familyOf(d.Value),
			Scope:     mapScope(d.Scope),
			Kind:      model.KindBan,
			Direction: model.DirInbound,
			Origin:    model.OriginCrowdSec,
			Backend:   string(model.OriginCrowdSec),
			Detail:    detail(d),
			NativeID:  strconv.FormatInt(d.ID, 10),
		}
		if dur, derr := time.ParseDuration(d.Duration); derr == nil && dur > 0 {
			exp := now.Add(dur)
			e.ExpiresAt = &exp
		}
		out = append(out, e)
	}
	return out, nil
}

// Ban adds a CrowdSec decision; the firewall bouncer enforces it.
func (b *Backend) Ban(ctx context.Context, req model.ActionRequest) (model.Result, error) {
	args := []string{"decisions", "add"}
	switch req.Scope {
	case model.ScopeRange:
		args = append(args, "--range", req.Value)
	case model.ScopeCountry:
		args = append(args, "--scope", "Country", "--value", req.Value)
	case model.ScopeAS:
		args = append(args, "--scope", "AS", "--value", req.Value)
	default:
		args = append(args, "--ip", req.Value)
	}
	if req.Duration > 0 {
		args = append(args, "--duration", req.Duration.String())
	}
	args = append(args, "--type", "ban")
	if req.Reason != "" {
		args = append(args, "--reason", req.Reason)
	}
	return b.run(ctx, req.DryRun, "ban", req.Value, [][]string{cmd("cscli", args)})
}

// Unban deletes the CrowdSec decision (by id when known, else by value).
func (b *Backend) Unban(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	args := []string{"decisions", "delete"}
	switch {
	case e.NativeID != "":
		args = append(args, "--id", e.NativeID)
	case e.Scope == model.ScopeRange:
		args = append(args, "--range", e.Value)
	default:
		args = append(args, "--ip", e.Value)
	}
	return b.run(ctx, dryRun, "unban", e.Value, [][]string{cmd("cscli", args)})
}

// Allow adds the value to omniban's managed CrowdSec allowlist (1.6.6+),
// creating the allowlist first if needed.
func (b *Backend) Allow(ctx context.Context, req model.ActionRequest) (model.Result, error) {
	create := cmd("cscli", []string{"allowlists", "create", allowlistName, "-d", "managed by omniban"})
	add := cmd("cscli", []string{"allowlists", "add", allowlistName, req.Value})
	if req.DryRun {
		return b.run(ctx, true, "allow", req.Value, [][]string{create, add})
	}
	// Best-effort create (it errors harmlessly if the allowlist already exists).
	_, _ = b.r.Run(ctx, create[0], create[1:]...)
	return b.run(ctx, false, "allow", req.Value, [][]string{add})
}

// RemoveAllow removes the value from omniban's managed CrowdSec allowlist.
func (b *Backend) RemoveAllow(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error) {
	remove := cmd("cscli", []string{"allowlists", "remove", allowlistName, e.Value})
	return b.run(ctx, dryRun, "unallow", e.Value, [][]string{remove})
}

// run executes (or, in dry-run, only records) one or more commands, returning a
// Result whose Commands field holds the exact invocations.
func (b *Backend) run(ctx context.Context, dryRun bool, action, value string, cmds [][]string) (model.Result, error) {
	res := model.Result{Backend: string(model.OriginCrowdSec), Action: action, Value: value, DryRun: dryRun}
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

func mapScope(scope string) model.Scope {
	switch strings.ToLower(scope) {
	case "range":
		return model.ScopeRange
	case "country":
		return model.ScopeCountry
	case "as":
		return model.ScopeAS
	default:
		return model.ScopeIP
	}
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

func detail(d cscliDecision) string {
	if d.Scenario != "" {
		return d.Scenario
	}
	return d.Origin
}
