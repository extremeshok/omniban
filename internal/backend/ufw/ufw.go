// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

// Package ufw adapts the Uncomplicated Firewall. Rules are managed via the ufw
// CLI; note that deleting a numbered rule renumbers the rest, so bulk deletes
// must run highest-number-first.
package ufw

import (
	"context"
	"strings"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// Backend is the UFW adapter.
type Backend struct {
	backend.Unimplemented
	r exec.Runner
}

// New constructs a UFW adapter.
func New(r exec.Runner) *Backend { return &Backend{r: r} }

// Name returns the backend identifier.
func (b *Backend) Name() string { return string(model.OriginUFW) }

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

// Detect probes for ufw and whether it reports an active status.
func (b *Backend) Detect(ctx context.Context) (backend.Detection, error) {
	var d backend.Detection
	if backend.FirstInstalled(b.r, "ufw") == "" {
		return d, nil
	}
	d.Installed = true
	if res, err := b.r.Run(ctx, "ufw", "status"); err == nil {
		d.Active = strings.Contains(strings.ToLower(res.Out()), "status: active")
	} else {
		d.Active = backend.ServiceActive(ctx, b.r, "ufw")
	}
	d.Enforcing = d.Active
	return d, nil
}
