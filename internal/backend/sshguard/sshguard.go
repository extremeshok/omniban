// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

// Package sshguard adapts sshguard, a lightweight SSH brute-force IDS that
// blocks via an nftables/ipset set and whitelists via /etc/sshguard/whitelist.
package sshguard

import (
	"context"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// Backend is the sshguard adapter.
type Backend struct {
	backend.Unimplemented
	r exec.Runner

	// whitelist is the sshguard allowlist file; overridable in tests.
	whitelist string
}

// New constructs an sshguard adapter.
func New(r exec.Runner) *Backend {
	return &Backend{r: r, whitelist: "/etc/sshguard/whitelist"}
}

// Name returns the backend identifier.
func (b *Backend) Name() string { return string(model.OriginSSHGuard) }

// Capabilities describes what the adapter supports.
func (b *Backend) Capabilities() backend.Capabilities {
	return backend.Capabilities{
		Layer:          model.LayerIDS,
		Directions:     []model.Direction{model.DirInbound},
		Scopes:         []model.Scope{model.ScopeIP, model.ScopeRange},
		CanBan:         false, // sshguard auto-bans; omniban does not create bans
		CanUnban:       true,  // best-effort: delete the nftables set element
		CanAllow:       true,  // via /etc/sshguard/whitelist
		CanRemoveAllow: true,
		SupportsCIDR:   true,
		SupportsIPv6:   true,
	}
}

// Detect probes for the sshguard binary, service, and config.
func (b *Backend) Detect(ctx context.Context) (backend.Detection, error) {
	var d backend.Detection
	if backend.FirstInstalled(b.r, "sshguard") == "" && !backend.FileExists("/etc/sshguard/sshguard.conf") {
		return d, nil
	}
	d.Installed = true
	d.Active = backend.ServiceActive(ctx, b.r, "sshguard")
	d.Enforcing = d.Active
	return d, nil
}
