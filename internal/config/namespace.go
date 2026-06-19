// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package config

import "strings"

// Owned namespaces. omniban only ever writes to these; everything else is read
// for attribution and never modified.
const (
	// NamePrefix tags every resource omniban creates.
	NamePrefix = "omniban"

	// NftTable is the dedicated nftables table (family inet).
	NftTable = "omniban"
	NftSet4  = "deny4"
	NftSet6  = "deny6"

	// IptablesChainIn/Out are the dedicated iptables chains.
	IptablesChainIn  = "OMNIBAN_INPUT"
	IptablesChainOut = "OMNIBAN_OUTPUT"

	// IPSetDeny4/6 are the dedicated ipset set names.
	IPSetDeny4 = "omniban-deny4"
	IPSetDeny6 = "omniban-deny6"

	// HostsBeginMarker/HostsEndMarker delimit our managed /etc/hosts block.
	HostsBeginMarker = "# omniban BEGIN — managed sinkholes (do not edit between markers)"
	HostsEndMarker   = "# omniban END"

	// BlackholeFile persists null-routes for replay by the systemd oneshot.
	BlackholeFile = "/etc/omniban/blackhole-routes.conf"
)

// foreignPrefixes are resource-name prefixes owned by other tools. Resources
// matching these are surfaced for attribution but never written.
var foreignPrefixes = []string{
	"f2b-",     // fail2ban ipsets / chains
	"crowdsec", // crowdsec bouncer sets
	"fw-",      // firewalld
	"sshguard", // sshguard table/chain
	"chain_",   // firewalld nft chains
}

// IsForeignResource reports whether a set/chain/table name belongs to another
// tool (and must therefore never be modified by omniban).
func IsForeignResource(name string) bool {
	n := strings.ToLower(name)
	if strings.HasPrefix(n, strings.ToLower(NamePrefix)) {
		return false
	}
	for _, p := range foreignPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}
