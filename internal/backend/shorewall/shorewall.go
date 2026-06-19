// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

// Package shorewall adapts Shorewall via its dynamic blacklist CLI
// (shorewall drop/reject/allow, show dynamic, save).
package shorewall

import (
	"context"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// Backend is the Shorewall adapter.
type Backend struct {
	backend.Unimplemented
	r exec.Runner
}

// New constructs a Shorewall adapter.
func New(r exec.Runner) *Backend { return &Backend{r: r} }

// Name returns the backend identifier.
func (b *Backend) Name() string { return string(model.OriginShorewall) }

// Capabilities describes what the adapter supports.
func (b *Backend) Capabilities() backend.Capabilities {
	return backend.Capabilities{
		Layer:          model.LayerFirewall,
		Directions:     []model.Direction{model.DirInbound},
		Scopes:         []model.Scope{model.ScopeIP, model.ScopeRange},
		CanBan:         true,
		CanUnban:       true,
		CanAllow:       false,
		CanRemoveAllow: false,
		SupportsCIDR:   true,
		SupportsIPv6:   true,
	}
}

// Detect probes for the shorewall binary and running state.
func (b *Backend) Detect(ctx context.Context) (backend.Detection, error) {
	var d backend.Detection
	if backend.FirstInstalled(b.r, "shorewall") == "" {
		return d, nil
	}
	d.Installed = true
	d.Active = backend.ServiceActive(ctx, b.r, "shorewall")
	d.Enforcing = d.Active
	if res, err := b.r.Run(ctx, "shorewall", "version"); err == nil {
		d.Version = backend.FirstLine(res.Out())
	}
	return d, nil
}
