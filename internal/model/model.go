// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

// Package model defines the backend-agnostic domain types shared across omniban:
// the unified Entry that every backend reports, and the ActionRequest/Result
// pair that drives ban/unban/allow operations.
package model

import "time"

// Origin is the true owner of an entry — the tool that created and manages it.
// Attribution favours the owner over any downstream enforcement layer.
type Origin string

// Known backend origins.
const (
	OriginManual      Origin = "manual"
	OriginFail2ban    Origin = "fail2ban"
	OriginCrowdSec    Origin = "crowdsec"
	OriginSSHGuard    Origin = "sshguard"
	OriginCSF         Origin = "csf"
	OriginAPF         Origin = "apf"
	OriginBFD         Origin = "bfd"
	OriginDenyHosts   Origin = "denyhosts"
	OriginSuricata    Origin = "suricata"
	OriginWazuh       Origin = "wazuh"
	OriginUFW         Origin = "ufw"
	OriginFirewalld   Origin = "firewalld"
	OriginShorewall   Origin = "shorewall"
	OriginNftables    Origin = "nftables"
	OriginIptables    Origin = "iptables"
	OriginIPSet       Origin = "ipset"
	OriginHAProxy     Origin = "haproxy"
	OriginBunkerWeb   Origin = "bunkerweb"
	OriginModSecurity Origin = "modsecurity"
	OriginBlackhole   Origin = "blackhole"
	OriginHosts       Origin = "hosts"
)

// Family distinguishes IPv4, IPv6, and domain-name entries.
type Family string

// Address families.
const (
	FamilyIPv4   Family = "ipv4"
	FamilyIPv6   Family = "ipv6"
	FamilyDomain Family = "domain"
)

// Scope is the kind of value an entry targets.
type Scope string

// Entry scopes.
const (
	ScopeIP      Scope = "ip"
	ScopeRange   Scope = "range" // CIDR
	ScopeDomain  Scope = "domain"
	ScopeCountry Scope = "country"
	ScopeAS      Scope = "as"
)

// Kind separates blocks (ban) from allowlist entries (allow).
type Kind string

// Entry kinds.
const (
	KindBan   Kind = "ban"
	KindAllow Kind = "allow"
)

// Layer classifies where a backend operates.
type Layer string

// Backend layers.
const (
	LayerIDS      Layer = "ids"      // detects + creates bans (fail2ban, crowdsec, suricata, wazuh, ...)
	LayerFirewall Layer = "firewall" // drops packets (ufw, firewalld, nft, shorewall, ...)
	LayerProxy    Layer = "proxy"    // load balancer / reverse proxy (haproxy)
	LayerWAF      Layer = "waf"      // web application firewall (bunkerweb, modsecurity)
	LayerRouting  Layer = "routing"  // blackhole routes
	LayerDNS      Layer = "dns"      // /etc/hosts sinkhole
)

// Direction is the traffic direction an entry affects.
type Direction string

// Traffic directions.
const (
	DirInbound  Direction = "inbound"
	DirOutbound Direction = "outbound"
	DirBoth     Direction = "both"
)

// Entry is a single ban or allow as reported by a backend, after normalization.
type Entry struct {
	Value      string     `json:"value"` // IP, CIDR, domain, country code, or ASN
	Family     Family     `json:"family"`
	Scope      Scope      `json:"scope"`
	Kind       Kind       `json:"kind"`
	Direction  Direction  `json:"direction"`
	Origin     Origin     `json:"origin"`             // true owner
	Backend    string     `json:"backend"`            // backend that reported it
	Detail     string     `json:"detail,omitempty"`   // jail (fail2ban), scenario (crowdsec), ...
	Hostname   string     `json:"hostname,omitempty"` // original hostname if added by name
	Reason     string     `json:"reason,omitempty"`
	CreatedAt  *time.Time `json:"created_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"` // nil = permanent
	NativeID   string     `json:"native_id,omitempty"`  // decision id / ufw rule number / nft handle / ...
	AlsoSeenIn []string   `json:"also_seen_in,omitempty"`
	External   bool       `json:"external,omitempty"` // user-added /etc/hosts sinkhole outside our block
	Raw        string     `json:"-"`                  // raw source line, for debugging
}

// ActionRequest describes a ban/unban/allow/unallow to perform.
type ActionRequest struct {
	Value     string
	Reason    string
	Scope     Scope
	Kind      Kind
	Direction Direction
	Backend   string        // target backend ("" = auto-select); the CLI --via flag
	Duration  time.Duration // 0 = permanent
	DryRun    bool
}

// Result reports the outcome of an action. Commands holds the exact native
// command(s) or file edits that were (or, in dry-run, would be) performed.
type Result struct {
	Backend  string   `json:"backend"`
	Action   string   `json:"action"`
	Value    string   `json:"value"`
	Commands []string `json:"commands,omitempty"`
	Changed  bool     `json:"changed"`
	DryRun   bool     `json:"dry_run"`
	Message  string   `json:"message,omitempty"`
}
