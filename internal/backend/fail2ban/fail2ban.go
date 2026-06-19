// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

// Package fail2ban adapts fail2ban. Bans are per-jail and enforced into the
// firewall by the jail's banaction; unbans must go through fail2ban-client so
// the jail does not re-add them.
package fail2ban

import (
	"context"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// Backend is the fail2ban adapter.
type Backend struct {
	backend.Unimplemented
	r exec.Runner
}

// New constructs a fail2ban adapter.
func New(r exec.Runner) *Backend { return &Backend{r: r} }

// Name returns the backend identifier.
func (b *Backend) Name() string { return string(model.OriginFail2ban) }

// Capabilities describes what the adapter supports.
func (b *Backend) Capabilities() backend.Capabilities {
	return backend.Capabilities{
		Layer:          model.LayerIDS,
		Directions:     []model.Direction{model.DirInbound},
		Scopes:         []model.Scope{model.ScopeIP},
		CanBan:         true,
		CanUnban:       true,
		CanAllow:       true, // via ignoreip
		CanRemoveAllow: true,
		SupportsCIDR:   false, // bans are per-IP; CIDR only in ignoreip
		SupportsIPv6:   true,
	}
}

// Detect probes for fail2ban-client and the fail2ban service.
func (b *Backend) Detect(ctx context.Context) (backend.Detection, error) {
	var d backend.Detection
	if backend.FirstInstalled(b.r, "fail2ban-client") == "" {
		return d, nil
	}
	d.Installed = true
	d.Active = backend.ServiceActive(ctx, b.r, "fail2ban")
	d.Enforcing = d.Active
	if res, err := b.r.Run(ctx, "fail2ban-client", "version"); err == nil {
		d.Version = backend.FirstLine(res.Out())
	}
	return d, nil
}
