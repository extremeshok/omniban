// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

// Package all is the backend registry. It imports every adapter and returns
// them as a slice; keeping it separate from package backend avoids an import
// cycle (adapters import backend, the registry imports the adapters).
package all

import (
	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/backend/apf"
	"github.com/extremeshok/omniban/internal/backend/blackhole"
	"github.com/extremeshok/omniban/internal/backend/bunkerweb"
	"github.com/extremeshok/omniban/internal/backend/crowdsec"
	"github.com/extremeshok/omniban/internal/backend/csf"
	"github.com/extremeshok/omniban/internal/backend/denyhosts"
	"github.com/extremeshok/omniban/internal/backend/fail2ban"
	"github.com/extremeshok/omniban/internal/backend/firewalld"
	"github.com/extremeshok/omniban/internal/backend/haproxy"
	"github.com/extremeshok/omniban/internal/backend/hosts"
	"github.com/extremeshok/omniban/internal/backend/ipset"
	"github.com/extremeshok/omniban/internal/backend/iptables"
	"github.com/extremeshok/omniban/internal/backend/modsecurity"
	"github.com/extremeshok/omniban/internal/backend/nftables"
	"github.com/extremeshok/omniban/internal/backend/shorewall"
	"github.com/extremeshok/omniban/internal/backend/sshguard"
	"github.com/extremeshok/omniban/internal/backend/suricata"
	"github.com/extremeshok/omniban/internal/backend/ufw"
	"github.com/extremeshok/omniban/internal/backend/wazuh"
	"github.com/extremeshok/omniban/internal/exec"
)

// All returns one instance of every backend adapter, bound to the runner.
// Order is IDS → firewall → proxy → WAF → routing/DNS, which is also the default
// display order; the manager applies attribution precedence explicitly.
func All(r exec.Runner) []backend.Backend {
	return []backend.Backend{
		// IDS / detection
		crowdsec.New(r),
		fail2ban.New(r),
		sshguard.New(r),
		csf.New(r),
		apf.New(r),
		denyhosts.New(r),
		suricata.New(r),
		wazuh.New(r),
		// firewall / enforcement
		ufw.New(r),
		firewalld.New(r),
		shorewall.New(r),
		nftables.New(r),
		iptables.New(r),
		ipset.New(r),
		// proxy / WAF
		haproxy.New(r),
		bunkerweb.New(r),
		modsecurity.New(r),
		// routing / DNS
		blackhole.New(r),
		hosts.New(r),
	}
}
