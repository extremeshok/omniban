// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

// Package manager orchestrates the registered backends: detection, the unified
// view, cross-backend warnings, and (from M2) routing of ban/unban/allow
// actions to the owning backend. M1 implements detection and status only.
package manager

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/extremeshok/omniban/internal/audit"
	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/backend/all"
	"github.com/extremeshok/omniban/internal/config"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
	"github.com/extremeshok/omniban/internal/resolve"
	"github.com/extremeshok/omniban/internal/safety"
)

// Manager owns the active backend set plus the shared runner, config, audit
// trail, undo journal, lockout guard, and resolver.
type Manager struct {
	cfg      config.Config
	runner   exec.Runner
	backends []backend.Backend

	audit    *audit.Logger
	journal  *safety.Journal
	guard    *safety.Guard
	resolver *resolve.Resolver
}

// New builds a Manager, dropping any backends named in cfg.DisabledBackends.
func New(cfg config.Config, r exec.Runner) *Manager {
	bs := all.All(r)
	if len(cfg.DisabledBackends) > 0 {
		disabled := make(map[string]bool, len(cfg.DisabledBackends))
		for _, d := range cfg.DisabledBackends {
			disabled[strings.ToLower(strings.TrimSpace(d))] = true
		}
		kept := bs[:0]
		for _, b := range bs {
			if !disabled[strings.ToLower(b.Name())] {
				kept = append(kept, b)
			}
		}
		bs = kept
	}
	return &Manager{
		cfg:      cfg,
		runner:   r,
		backends: bs,
		audit:    audit.New(cfg.LogFile),
		journal:  safety.NewJournal(cfg.StateDir),
		guard:    safety.Build(cfg.AdminAllowlist, os.Getenv),
		resolver: resolve.New(),
	}
}

// Backends returns the active backend set.
func (m *Manager) Backends() []backend.Backend { return m.backends }

// Guard returns the lockout-prevention guard.
func (m *Manager) Guard() *safety.Guard { return m.guard }

// Resolver returns the hostname resolver.
func (m *Manager) Resolver() *resolve.Resolver { return m.resolver }

// byName returns the active backend with the given name.
func (m *Manager) byName(name string) (backend.Backend, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, b := range m.backends {
		if strings.ToLower(b.Name()) == name {
			return b, true
		}
	}
	return nil, false
}

// Status pairs a backend with its detection result and capabilities.
type Status struct {
	Name         string               `json:"name"`
	Layer        model.Layer          `json:"layer"`
	Capabilities backend.Capabilities `json:"capabilities"`
	Detection    backend.Detection    `json:"detection"`
	Err          string               `json:"error,omitempty"`
}

// Detect probes every backend (sequentially, for deterministic output) and
// returns one Status per backend in registry order.
func (m *Manager) Detect(ctx context.Context) []Status {
	out := make([]Status, 0, len(m.backends))
	for _, b := range m.backends {
		st := Status{Name: b.Name(), Layer: b.Capabilities().Layer, Capabilities: b.Capabilities()}
		d, err := b.Detect(ctx)
		st.Detection = d
		if err != nil {
			st.Err = err.Error()
		}
		out = append(out, st)
	}
	return out
}

// CrossWarnings derives host-level advisories that span backends.
func (m *Manager) CrossWarnings(statuses []Status) []string {
	var warns []string

	var activeFirewalls []string
	for _, s := range statuses {
		if s.Layer == model.LayerFirewall && s.Detection.Active {
			activeFirewalls = append(activeFirewalls, s.Name)
		}
	}
	if len(activeFirewalls) > 1 {
		sort.Strings(activeFirewalls)
		target := m.ManualTarget(statuses)
		warns = append(warns, fmt.Sprintf(
			"multiple active firewall backends (%s); manual bans will target %q — set manual_ban_backend to override",
			strings.Join(activeFirewalls, ", "), target))
	}
	if len(activeFirewalls) == 0 {
		warns = append(warns, "no active firewall backend detected — manual IP bans have nowhere to land")
	}
	return warns
}

// manualTargetPriority is the auto-selection order for manual inbound bans.
var manualTargetPriority = []model.Origin{
	model.OriginCSF, model.OriginFirewalld, model.OriginUFW, model.OriginNftables, model.OriginIptables,
}

// ManualTarget chooses which firewall backend receives manual inbound bans: the
// configured one if set and active, else the highest-priority active firewall.
func (m *Manager) ManualTarget(statuses []Status) string {
	active := make(map[string]bool)
	for _, s := range statuses {
		if s.Layer == model.LayerFirewall && s.Detection.Active {
			active[s.Name] = true
		}
	}
	if t := strings.ToLower(strings.TrimSpace(m.cfg.ManualBanBackend)); t != "" {
		if active[t] {
			return t
		}
	}
	for _, o := range manualTargetPriority {
		if active[string(o)] {
			return string(o)
		}
	}
	return ""
}
