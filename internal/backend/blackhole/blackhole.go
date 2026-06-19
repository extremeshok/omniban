// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

// Package blackhole adapts null-routing via "ip route add blackhole". This
// drops traffic to a destination (affecting both directions) and is persisted
// to omniban's own routes file, replayed on boot by a systemd oneshot.
package blackhole

import (
	"context"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/config"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// Backend is the blackhole-route adapter.
type Backend struct {
	backend.Unimplemented
	r exec.Runner

	// routesFile persists null-routes for boot replay; overridable in tests.
	routesFile string
}

// New constructs a blackhole adapter.
func New(r exec.Runner) *Backend {
	return &Backend{r: r, routesFile: config.BlackholeFile}
}

// Name returns the backend identifier.
func (b *Backend) Name() string { return string(model.OriginBlackhole) }

// Capabilities describes what the adapter supports.
func (b *Backend) Capabilities() backend.Capabilities {
	return backend.Capabilities{
		Layer:        model.LayerRouting,
		Directions:   []model.Direction{model.DirBoth},
		Scopes:       []model.Scope{model.ScopeIP, model.ScopeRange},
		CanBan:       true,
		CanUnban:     true,
		SupportsCIDR: true,
		SupportsIPv6: true,
	}
}

// Detect probes for the iproute2 "ip" binary.
func (b *Backend) Detect(_ context.Context) (backend.Detection, error) {
	var d backend.Detection
	if backend.FirstInstalled(b.r, "ip") == "" {
		return d, nil
	}
	d.Installed = true
	d.Active = true
	d.Enforcing = true
	return d, nil
}
