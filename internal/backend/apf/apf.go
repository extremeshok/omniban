// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

// Package apf adapts Advanced Policy Firewall (APF) and its companion Brute
// Force Detection daemon (BFD). APF owns the deny/allow rule files; BFD detects
// attacks and calls "apf -d", tagging entries with a {bfd.*} comment which we
// use for attribution.
package apf

import (
	"context"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

const (
	apfBin = "/usr/local/sbin/apf"
	bfdBin = "/usr/local/sbin/bfd"
)

// Backend is the APF/BFD adapter.
type Backend struct {
	backend.Unimplemented
	r exec.Runner
}

// New constructs an APF adapter.
func New(r exec.Runner) *Backend { return &Backend{r: r} }

// Name returns the backend identifier.
func (b *Backend) Name() string { return string(model.OriginAPF) }

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
		SupportsExpiry: true, // apf -td temporary deny
	}
}

// Detect probes for the apf binary/config and notes whether BFD is present.
func (b *Backend) Detect(ctx context.Context) (backend.Detection, error) {
	var d backend.Detection
	if backend.FirstInstalled(b.r, "apf", apfBin) == "" && !backend.FileExists("/etc/apf/conf.apf") {
		return d, nil
	}
	d.Installed = true
	d.Active = backend.FileExists("/etc/apf/deny_hosts.rules") || backend.ServiceActive(ctx, b.r, "apf")
	d.Enforcing = d.Active
	if backend.FirstInstalled(b.r, "bfd", bfdBin) != "" {
		d.Warnings = append(d.Warnings, "BFD detected: brute-force bans (tagged {bfd.*}) are managed by BFD via APF")
	}
	return d, nil
}
