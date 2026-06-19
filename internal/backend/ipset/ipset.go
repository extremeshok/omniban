// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

// Package ipset adapts raw ipset. A set only drops traffic when an
// iptables/nft rule references it, so this adapter ensures a referencing rule
// exists for its own omniban-deny4/6 sets. Foreign sets (f2b-*, crowdsec-*,
// fw-*) are read for attribution only.
package ipset

import (
	"context"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// Backend is the raw-ipset adapter.
type Backend struct {
	backend.Unimplemented
	r exec.Runner
}

// New constructs an ipset adapter.
func New(r exec.Runner) *Backend { return &Backend{r: r} }

// Name returns the backend identifier.
func (b *Backend) Name() string { return string(model.OriginIPSet) }

// Capabilities describes what the adapter supports.
func (b *Backend) Capabilities() backend.Capabilities {
	return backend.Capabilities{
		Layer:                 model.LayerFirewall,
		Directions:            []model.Direction{model.DirInbound},
		Scopes:                []model.Scope{model.ScopeIP, model.ScopeRange},
		CanBan:                true,
		CanUnban:              true,
		RequiresReferenceRule: true,
		SupportsCIDR:          true,
		SupportsIPv6:          true,
		SupportsExpiry:        true, // set element timeouts
	}
}

// Detect probes for the ipset binary.
func (b *Backend) Detect(ctx context.Context) (backend.Detection, error) {
	var d backend.Detection
	if backend.FirstInstalled(b.r, "ipset") == "" {
		return d, nil
	}
	d.Installed = true
	d.Active = true
	if res, err := b.r.Run(ctx, "ipset", "version"); err == nil {
		d.Version = backend.FirstLine(res.Out())
	}
	return d, nil
}
