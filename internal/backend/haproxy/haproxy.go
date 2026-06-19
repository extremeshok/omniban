// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

// Package haproxy adapts HAProxy via its runtime stats socket: IP blocks are
// entries in an omniban-owned map (show/set/del map) referenced by an ACL, so
// changes apply with no reload.
package haproxy

import (
	"context"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// Backend is the HAProxy adapter.
type Backend struct {
	backend.Unimplemented
	r       exec.Runner
	socket  string // runtime stats socket
	denyMap string // omniban-owned deny map
}

// New constructs a HAProxy adapter.
func New(r exec.Runner) *Backend {
	return &Backend{r: r, socket: "/run/haproxy/admin.sock", denyMap: "/etc/haproxy/omniban_deny.map"}
}

// Name returns the backend identifier.
func (b *Backend) Name() string { return string(model.OriginHAProxy) }

// Capabilities describes what the adapter supports.
func (b *Backend) Capabilities() backend.Capabilities {
	return backend.Capabilities{
		Layer:        model.LayerProxy,
		Directions:   []model.Direction{model.DirInbound},
		Scopes:       []model.Scope{model.ScopeIP},
		CanBan:       true,
		CanUnban:     true,
		SupportsIPv6: true,
	}
}

// Detect probes for the haproxy binary and its runtime socket.
func (b *Backend) Detect(ctx context.Context) (backend.Detection, error) {
	var d backend.Detection
	if backend.FirstInstalled(b.r, "haproxy") == "" {
		return d, nil
	}
	d.Installed = true
	d.Active = backend.FileExists(b.socket) || backend.ServiceActive(ctx, b.r, "haproxy")
	d.Enforcing = d.Active
	if res, err := b.r.Run(ctx, "haproxy", "-v"); err == nil {
		d.Version = backend.FirstLine(res.Out())
	}
	if d.Installed && backend.FirstInstalled(b.r, "socat") == "" {
		d.Warnings = append(d.Warnings, "socat not found — required to talk to the HAProxy runtime socket")
	}
	return d, nil
}
