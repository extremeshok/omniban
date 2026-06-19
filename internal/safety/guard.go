// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

// Package safety prevents self-lockout and records an undo journal. The guard
// refuses (without --force) to ban any address in the protected set: the
// current SSH client, loopback, the host's own addresses, and the configured
// admin allowlist.
package safety

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Guard holds the protected prefix set for lockout prevention.
type Guard struct {
	protected []netip.Prefix
}

// Build assembles a Guard from the environment (SSH client, host interfaces,
// loopback) plus the configured admin allowlist.
func Build(adminAllowlist []string, env func(string) string) *Guard {
	g := &Guard{}
	g.protected = append(g.protected, loopbackPrefixes()...)
	g.protected = append(g.protected, sshClientPrefixes(env("SSH_CONNECTION"), env("SSH_CLIENT"))...)
	g.protected = append(g.protected, hostInterfacePrefixes()...)
	g.protected = append(g.protected, parsePrefixes(adminAllowlist)...)
	return g
}

// Protected returns the protected prefixes (for display/debugging).
func (g *Guard) Protected() []netip.Prefix { return g.protected }

// IsProtected reports whether banning value (an IP or CIDR) would touch the
// protected set, with a human-readable reason naming the match.
func (g *Guard) IsProtected(value string) (bool, string) {
	hit, p, err := intersects(g.protected, value)
	if err != nil || !hit {
		return false, ""
	}
	return true, fmt.Sprintf("%s overlaps the protected address %s (use --force to override)", value, p)
}

// intersects reports whether value intersects any prefix in set.
func intersects(set []netip.Prefix, value string) (bool, netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if addr, err := netip.ParseAddr(value); err == nil {
		addr = addr.Unmap()
		for _, p := range set {
			if p.Contains(addr) {
				return true, p, nil
			}
		}
		return false, netip.Prefix{}, nil
	}
	if pfx, err := netip.ParsePrefix(value); err == nil {
		pfx = pfx.Masked()
		for _, p := range set {
			if p.Overlaps(pfx) {
				return true, p, nil
			}
		}
		return false, netip.Prefix{}, nil
	}
	// Non-IP values (domains) cannot lock out network access here.
	return false, netip.Prefix{}, fmt.Errorf("not an IP or CIDR: %q", value)
}

func loopbackPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}
}

// sshClientPrefixes extracts the SSH client IP from SSH_CONNECTION
// ("<client> <cport> <server> <sport>") or SSH_CLIENT ("<client> <cport> <sport>").
func sshClientPrefixes(sshConnection, sshClient string) []netip.Prefix {
	for _, v := range []string{sshConnection, sshClient} {
		fields := strings.Fields(v)
		if len(fields) == 0 {
			continue
		}
		if addr, err := netip.ParseAddr(fields[0]); err == nil {
			return []netip.Prefix{hostPrefix(addr.Unmap())}
		}
	}
	return nil
}

// hostInterfacePrefixes returns the host's own assigned addresses as host routes.
func hostInterfacePrefixes() []netip.Prefix {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if addr, ok := netip.AddrFromSlice(ipNet.IP); ok {
			out = append(out, hostPrefix(addr.Unmap()))
		}
	}
	return out
}

func parsePrefixes(values []string) []netip.Prefix {
	var out []netip.Prefix
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if addr, err := netip.ParseAddr(v); err == nil {
			out = append(out, hostPrefix(addr.Unmap()))
			continue
		}
		if p, err := netip.ParsePrefix(v); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

// hostPrefix returns the single-host prefix (/32 or /128) for addr.
func hostPrefix(addr netip.Addr) netip.Prefix {
	return netip.PrefixFrom(addr, addr.BitLen())
}
