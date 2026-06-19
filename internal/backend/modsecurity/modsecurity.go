// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

// Package modsecurity adapts a ModSecurity / OWASP-CRS WAF (on nginx or Apache)
// by managing an IP blocklist file consumed by a "@ipMatchFromFile" SecRule,
// reloading the web server to apply changes.
package modsecurity

import (
	"context"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// Backend is the ModSecurity (OWASP CRS) adapter.
type Backend struct {
	backend.Unimplemented
	r         exec.Runner
	blocklist string // managed @ipMatchFromFile blocklist (one IP/CIDR per line)
	reloadBin string // web server used to apply changes (nginx by default)
}

// New constructs a ModSecurity adapter.
func New(r exec.Runner) *Backend {
	return &Backend{r: r, blocklist: "/etc/modsecurity/omniban-blocklist.txt", reloadBin: "nginx"}
}

// Name returns the backend identifier.
func (b *Backend) Name() string { return string(model.OriginModSecurity) }

// Capabilities describes what the adapter supports.
func (b *Backend) Capabilities() backend.Capabilities {
	return backend.Capabilities{
		Layer:        model.LayerWAF,
		Directions:   []model.Direction{model.DirInbound},
		Scopes:       []model.Scope{model.ScopeIP, model.ScopeRange},
		CanBan:       true,
		CanUnban:     true,
		SupportsCIDR: true, // @ipMatchFromFile matches IPs and CIDRs
		SupportsIPv6: true,
	}
}

// Detect probes for a ModSecurity install (config dir or our blocklist).
func (b *Backend) Detect(ctx context.Context) (backend.Detection, error) {
	var d backend.Detection
	if !backend.FileExists("/etc/modsecurity") && !backend.FileExists("/etc/nginx/modsecurity.conf") &&
		!backend.FileExists("/etc/nginx/modsec") && !backend.FileExists(b.blocklist) {
		return d, nil
	}
	d.Installed = true
	d.Active = backend.ServiceActive(ctx, b.r, "nginx") || backend.FirstInstalled(b.r, b.reloadBin) != ""
	d.Enforcing = d.Active
	return d, nil
}
