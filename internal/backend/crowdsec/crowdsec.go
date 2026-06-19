// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

// Package crowdsec adapts CrowdSec. Bans are LAPI "decisions" managed via cscli
// and enforced into the firewall by a bouncer — omniban never touches the
// firewall directly for CrowdSec, and warns when no bouncer is registered.
package crowdsec

import (
	"context"
	"strings"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// Backend is the CrowdSec adapter.
type Backend struct {
	backend.Unimplemented
	r exec.Runner
}

// New constructs a CrowdSec adapter.
func New(r exec.Runner) *Backend { return &Backend{r: r} }

// Name returns the backend identifier.
func (b *Backend) Name() string { return string(model.OriginCrowdSec) }

// Capabilities describes what the adapter supports.
func (b *Backend) Capabilities() backend.Capabilities {
	return backend.Capabilities{
		Layer:          model.LayerIDS,
		Directions:     []model.Direction{model.DirInbound},
		Scopes:         []model.Scope{model.ScopeIP, model.ScopeRange, model.ScopeCountry, model.ScopeAS},
		CanBan:         true,
		CanUnban:       true,
		CanAllow:       true,
		CanRemoveAllow: true,
		SupportsCIDR:   true,
		SupportsIPv6:   true,
		SupportsExpiry: true,
	}
}

// Detect probes for cscli, the crowdsec service, and a registered bouncer.
func (b *Backend) Detect(ctx context.Context) (backend.Detection, error) {
	var d backend.Detection
	if backend.FirstInstalled(b.r, "cscli") == "" {
		return d, nil
	}
	d.Installed = true
	d.Active = backend.ServiceActive(ctx, b.r, "crowdsec")
	if res, err := b.r.Run(ctx, "cscli", "version"); err == nil {
		d.Version = backend.FirstLine(res.Out())
	}
	if d.Active {
		if res, err := b.r.Run(ctx, "cscli", "bouncers", "list", "-o", "json"); err == nil {
			switch strings.TrimSpace(res.Out()) {
			case "", "[]", "null":
				d.Warnings = append(d.Warnings,
					"crowdsec is running but no firewall bouncer is registered — decisions are NOT being enforced")
			default:
				d.Enforcing = true
			}
		}
	}
	return d, nil
}
