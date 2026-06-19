// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

// Package suricata adapts Suricata (7+) via its Unix command socket: IP blocks
// are managed as elements of a named dataset (dataset-add/remove/lookup), which
// IPS-mode rules drop on.
package suricata

import (
	"context"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// Backend is the Suricata adapter.
type Backend struct {
	backend.Unimplemented
	r         exec.Runner
	socket    string // suricata command socket
	set       string // omniban-owned dataset name
	stateFile string // dataset save/state file, read best-effort for ListBans
}

// New constructs a Suricata adapter.
func New(r exec.Runner) *Backend {
	return &Backend{
		r:         r,
		socket:    "/var/run/suricata/command.socket",
		set:       "omniban-deny",
		stateFile: "/var/lib/suricata/data/omniban-deny.lst",
	}
}

// Name returns the backend identifier.
func (b *Backend) Name() string { return string(model.OriginSuricata) }

// Capabilities describes what the adapter supports.
func (b *Backend) Capabilities() backend.Capabilities {
	return backend.Capabilities{
		Layer:        model.LayerIDS,
		Directions:   []model.Direction{model.DirInbound},
		Scopes:       []model.Scope{model.ScopeIP},
		CanBan:       true,
		CanUnban:     true,
		SupportsIPv6: true,
	}
}

// Detect probes for the suricata binary/socket and config.
func (b *Backend) Detect(ctx context.Context) (backend.Detection, error) {
	var d backend.Detection
	if backend.FirstInstalled(b.r, "suricata", "suricatasc") == "" &&
		!backend.FileExists("/etc/suricata/suricata.yaml") {
		return d, nil
	}
	d.Installed = true
	d.Active = backend.FileExists(b.socket) || backend.ServiceActive(ctx, b.r, "suricata")
	d.Enforcing = d.Active
	if res, err := b.r.Run(ctx, "suricata", "-V"); err == nil {
		d.Version = backend.FirstLine(res.Out())
	}
	return d, nil
}
