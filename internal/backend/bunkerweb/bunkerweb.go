// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

// Package bunkerweb adapts BunkerWeb (an OWASP-CRS-based WAF) via its bwcli
// ban interface (bwcli ban / unban / bans).
package bunkerweb

import (
	"context"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// Backend is the BunkerWeb adapter.
type Backend struct {
	backend.Unimplemented
	r exec.Runner
}

// New constructs a BunkerWeb adapter.
func New(r exec.Runner) *Backend { return &Backend{r: r} }

// Name returns the backend identifier.
func (b *Backend) Name() string { return string(model.OriginBunkerWeb) }

// Capabilities describes what the adapter supports.
func (b *Backend) Capabilities() backend.Capabilities {
	return backend.Capabilities{
		Layer:          model.LayerWAF,
		Directions:     []model.Direction{model.DirInbound},
		Scopes:         []model.Scope{model.ScopeIP},
		CanBan:         true,
		CanUnban:       true,
		CanAllow:       true,
		CanRemoveAllow: true,
		SupportsIPv6:   true,
		SupportsExpiry: true,
	}
}

// Detect probes for the bwcli binary.
func (b *Backend) Detect(ctx context.Context) (backend.Detection, error) {
	var d backend.Detection
	if backend.FirstInstalled(b.r, "bwcli") == "" {
		return d, nil
	}
	d.Installed = true
	d.Active = backend.ServiceActive(ctx, b.r, "bunkerweb") || backend.FileExists("/etc/bunkerweb")
	d.Enforcing = d.Active
	return d, nil
}
