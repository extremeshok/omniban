// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

// Package csf adapts ConfigServer Security & Firewall (CSF/LFD), common on
// cPanel/CloudLinux hosts. Bans live in /etc/csf/csf.deny and are driven by the
// csf CLI; LFD is the brute-force detection daemon layered on top.
package csf

import (
	"context"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// Backend is the CSF/LFD adapter.
type Backend struct {
	backend.Unimplemented
	r exec.Runner

	// File paths are overridable so tests can point them at temp files.
	denyFile   string
	allowFile  string
	ignoreFile string
}

// New constructs a CSF adapter with the standard /etc/csf file locations.
func New(r exec.Runner) *Backend {
	return &Backend{
		r:          r,
		denyFile:   "/etc/csf/csf.deny",
		allowFile:  "/etc/csf/csf.allow",
		ignoreFile: "/etc/csf/csf.ignore",
	}
}

// Name returns the backend identifier.
func (b *Backend) Name() string { return string(model.OriginCSF) }

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
		SupportsExpiry: true, // csf -td/-ta temporary entries
	}
}

// Detect probes for the csf binary and config, and the lfd service.
func (b *Backend) Detect(ctx context.Context) (backend.Detection, error) {
	var d backend.Detection
	if backend.FirstInstalled(b.r, "csf", "/usr/sbin/csf") == "" && !backend.FileExists("/etc/csf/csf.conf") {
		return d, nil
	}
	d.Installed = true
	d.Active = backend.ServiceActive(ctx, b.r, "lfd") || backend.FileExists("/etc/csf/csf.conf")
	d.Enforcing = d.Active
	if res, err := b.r.Run(ctx, "csf", "--version"); err == nil {
		d.Version = backend.FirstLine(res.Out())
	}
	return d, nil
}
