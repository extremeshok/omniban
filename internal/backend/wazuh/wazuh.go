// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

// Package wazuh adapts Wazuh/OSSEC active-response: IP blocks are applied and
// removed through the firewall-drop active-response script, and listed from the
// active-responses log.
package wazuh

import (
	"context"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

const ossecDir = "/var/ossec"

// Backend is the Wazuh/OSSEC adapter.
type Backend struct {
	backend.Unimplemented
	r   exec.Runner
	dir string // OSSEC/Wazuh install dir
}

// New constructs a Wazuh adapter.
func New(r exec.Runner) *Backend { return &Backend{r: r, dir: ossecDir} }

// Name returns the backend identifier.
func (b *Backend) Name() string { return string(model.OriginWazuh) }

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

// Detect probes for the Wazuh/OSSEC install and service.
func (b *Backend) Detect(ctx context.Context) (backend.Detection, error) {
	var d backend.Detection
	if !backend.FileExists(b.dir+"/bin/wazuh-control") && !backend.FileExists(b.dir) {
		return d, nil
	}
	d.Installed = true
	d.Active = backend.ServiceActive(ctx, b.r, "wazuh-agent") ||
		backend.ServiceActive(ctx, b.r, "wazuh-manager") ||
		backend.ServiceActive(ctx, b.r, "ossec")
	d.Enforcing = d.Active
	return d, nil
}
