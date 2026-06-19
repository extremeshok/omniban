// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

// Package firewalld adapts firewalld (the default on RHEL clones / CloudLinux).
// omniban manages its bans and allows as permanent source-address rich rules so
// they survive restarts, applying changes with firewall-cmd --reload.
package firewalld

import (
	"context"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// Backend is the firewalld adapter.
type Backend struct {
	backend.Unimplemented
	r exec.Runner
}

// New constructs a firewalld adapter.
func New(r exec.Runner) *Backend { return &Backend{r: r} }

// Name returns the backend identifier.
func (b *Backend) Name() string { return string(model.OriginFirewalld) }

// Capabilities describes what the adapter supports.
func (b *Backend) Capabilities() backend.Capabilities {
	return backend.Capabilities{
		Layer:          model.LayerFirewall,
		Directions:     []model.Direction{model.DirInbound},
		Scopes:         []model.Scope{model.ScopeIP, model.ScopeRange},
		CanBan:         true,
		CanUnban:       true,
		CanAllow:       true,
		CanRemoveAllow: true,
		SupportsCIDR:   true,
		SupportsIPv6:   true,
	}
}

// Detect probes for firewall-cmd and the firewalld service.
func (b *Backend) Detect(ctx context.Context) (backend.Detection, error) {
	var d backend.Detection
	if backend.FirstInstalled(b.r, "firewall-cmd") == "" {
		return d, nil
	}
	d.Installed = true
	d.Active = backend.ServiceActive(ctx, b.r, "firewalld")
	d.Enforcing = d.Active
	if res, err := b.r.Run(ctx, "firewall-cmd", "--version"); err == nil {
		d.Version = backend.FirstLine(res.Out())
	}
	return d, nil
}
