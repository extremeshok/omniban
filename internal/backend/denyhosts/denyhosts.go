// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

// Package denyhosts adapts DenyHosts. It has no management API, so omniban owns
// the coordination: stop the daemon, edit /etc/hosts.deny plus the work files,
// then restart. The daemon mishandles IPv6, so v6 bans warn and are steered to
// a firewall backend instead.
package denyhosts

import (
	"context"
	"path/filepath"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// Backend is the DenyHosts adapter.
type Backend struct {
	backend.Unimplemented
	r exec.Runner

	// File and service locations, overridable in tests. workDir holds the
	// DenyHosts work files ("hosts" and "hosts-restricted") that must be kept in
	// sync with hostsDeny; allowedHosts is the DenyHosts allowlist.
	hostsDeny    string
	workDir      string
	allowedHosts string
	service      string
}

// New constructs a DenyHosts adapter with the distribution default paths.
func New(r exec.Runner) *Backend {
	workDir := "/var/lib/denyhosts"
	return &Backend{
		r:            r,
		hostsDeny:    "/etc/hosts.deny",
		workDir:      workDir,
		allowedHosts: filepath.Join(workDir, "allowed-hosts"),
		service:      "denyhosts",
	}
}

// Name returns the backend identifier.
func (b *Backend) Name() string { return string(model.OriginDenyHosts) }

// Capabilities describes what the adapter supports.
func (b *Backend) Capabilities() backend.Capabilities {
	return backend.Capabilities{
		Layer:          model.LayerIDS,
		Directions:     []model.Direction{model.DirInbound},
		Scopes:         []model.Scope{model.ScopeIP, model.ScopeRange},
		CanBan:         true,
		CanUnban:       true,
		CanAllow:       true, // allowed-hosts
		CanRemoveAllow: true,
		SupportsCIDR:   true,
		SupportsIPv6:   false, // daemon truncates IPv6
	}
}

// Detect probes for the denyhosts binary/config and service.
func (b *Backend) Detect(ctx context.Context) (backend.Detection, error) {
	var d backend.Detection
	if backend.FirstInstalled(b.r, "denyhosts", "/usr/sbin/denyhosts") == "" &&
		!backend.FileExists("/etc/denyhosts.conf") {
		return d, nil
	}
	d.Installed = true
	d.Active = backend.ServiceActive(ctx, b.r, "denyhosts")
	d.Enforcing = d.Active
	d.Warnings = append(d.Warnings, "DenyHosts mishandles IPv6 — manage IPv6 bans via a firewall backend")
	return d, nil
}
