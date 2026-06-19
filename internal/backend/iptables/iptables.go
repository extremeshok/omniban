// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

// Package iptables adapts raw iptables/ip6tables. omniban owns dedicated
// OMNIBAN_INPUT/OMNIBAN_OUTPUT chains; IPv4 and IPv6 are managed separately.
package iptables

import (
	"context"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// Backend is the raw-iptables adapter.
type Backend struct {
	backend.Unimplemented
	r exec.Runner
}

// New constructs an iptables adapter.
func New(r exec.Runner) *Backend { return &Backend{r: r} }

// Name returns the backend identifier.
func (b *Backend) Name() string { return string(model.OriginIptables) }

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

// Detect probes for the iptables binary and reports the backend variant.
func (b *Backend) Detect(ctx context.Context) (backend.Detection, error) {
	var d backend.Detection
	if backend.FirstInstalled(b.r, "iptables") == "" {
		return d, nil
	}
	d.Installed = true
	d.Active = true
	if res, err := b.r.Run(ctx, "iptables", "--version"); err == nil {
		d.Version = backend.FirstLine(res.Out())
	}
	return d, nil
}
