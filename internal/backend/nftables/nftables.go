// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

// Package nftables adapts raw nftables. omniban owns a dedicated "inet omniban"
// table with deny4/deny6 interval sets and a referencing drop rule; foreign
// tables (firewalld, sshguard, crowdsec) are read for attribution only.
package nftables

import (
	"context"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// Backend is the raw-nftables adapter.
type Backend struct {
	backend.Unimplemented
	r exec.Runner
}

// New constructs an nftables adapter.
func New(r exec.Runner) *Backend { return &Backend{r: r} }

// Name returns the backend identifier.
func (b *Backend) Name() string { return string(model.OriginNftables) }

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
		SupportsExpiry: true, // set element timeouts
	}
}

// Detect probes for the nft binary.
func (b *Backend) Detect(ctx context.Context) (backend.Detection, error) {
	var d backend.Detection
	if backend.FirstInstalled(b.r, "nft") == "" {
		return d, nil
	}
	d.Installed = true
	d.Active = true // the nft tool is usable whenever present
	if res, err := b.r.Run(ctx, "nft", "--version"); err == nil {
		d.Version = backend.FirstLine(res.Out())
	}
	return d, nil
}
