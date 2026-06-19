// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

// Package hosts adapts /etc/hosts domain sinkholes (outbound, domain-scoped).
// It scans the whole file for any 0.0.0.0 / 127.0.0.1 / :: / ::1 mapping —
// including ones a user added by hand outside omniban's managed block — and can
// remove any of them on request, while only ever adding inside the block.
package hosts

import (
	"context"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// Path is the hosts file managed by this adapter.
const Path = "/etc/hosts"

// Backend is the /etc/hosts sinkhole adapter.
type Backend struct {
	backend.Unimplemented
	r    exec.Runner
	path string
}

// New constructs a hosts adapter operating on the default /etc/hosts.
func New(r exec.Runner) *Backend { return &Backend{r: r, path: Path} }

// Name returns the backend identifier.
func (b *Backend) Name() string { return string(model.OriginHosts) }

// Capabilities describes what the adapter supports.
func (b *Backend) Capabilities() backend.Capabilities {
	return backend.Capabilities{
		Layer:        model.LayerDNS,
		Directions:   []model.Direction{model.DirOutbound},
		Scopes:       []model.Scope{model.ScopeDomain},
		CanBan:       true,
		CanUnban:     true,
		SupportsCIDR: false,
		SupportsIPv6: true, // ::1 / :: sinkhole targets
	}
}

// Detect always reports present: /etc/hosts exists on every Linux host.
func (b *Backend) Detect(_ context.Context) (backend.Detection, error) {
	return backend.Detection{
		Installed: backend.FileExists(b.path),
		Active:    backend.FileExists(b.path),
		Enforcing: backend.FileExists(b.path),
	}, nil
}
