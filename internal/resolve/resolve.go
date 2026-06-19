// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

// Package resolve turns a user query into matches against the unified entry
// list. It supports exact, CIDR-containment, wildcard/glob, and domain queries,
// and resolves hostnames to addresses for ban/check by name.
package resolve

import (
	"context"
	"net"
	"net/netip"
	"regexp"
	"strings"

	"github.com/extremeshok/omniban/internal/model"
)

// Matcher answers "does this entry match the query?" for one parsed query.
type Matcher struct {
	raw      string
	contains bool

	addr   *netip.Addr    // set when the query is a bare IP
	prefix *netip.Prefix  // set when the query is a CIDR
	domain string         // set when the query is a domain/host label
	glob   *regexp.Regexp // set when the query contains * or ?
}

// NewMatcher parses query into a Matcher. When contains is true, an IP query
// also matches CIDR entries that contain it (and vice-versa for CIDR queries).
func NewMatcher(query string, contains bool) Matcher {
	m := Matcher{raw: strings.TrimSpace(query), contains: contains}
	switch {
	case strings.ContainsAny(m.raw, "*?"):
		m.glob = globToRegexp(m.raw)
	default:
		if addr, err := netip.ParseAddr(m.raw); err == nil {
			a := addr.Unmap()
			m.addr = &a
			return m
		}
		if p, err := netip.ParsePrefix(m.raw); err == nil {
			pm := p.Masked()
			m.prefix = &pm
			return m
		}
		m.domain = strings.ToLower(strings.TrimSuffix(m.raw, "."))
	}
	return m
}

// Matches reports whether e satisfies the query.
func (m Matcher) Matches(e model.Entry) bool {
	switch {
	case m.glob != nil:
		return m.glob.MatchString(e.Value) ||
			(e.Hostname != "" && m.glob.MatchString(e.Hostname))
	case m.addr != nil:
		return m.matchAddr(e)
	case m.prefix != nil:
		return m.matchPrefix(e)
	case m.domain != "":
		return strings.EqualFold(e.Value, m.domain) ||
			(e.Hostname != "" && strings.EqualFold(e.Hostname, m.domain))
	}
	return false
}

func (m Matcher) matchAddr(e model.Entry) bool {
	if entryAddr, err := netip.ParseAddr(e.Value); err == nil {
		return entryAddr.Unmap() == *m.addr
	}
	if entryPfx, err := netip.ParsePrefix(e.Value); err == nil {
		entryPfx = entryPfx.Masked()
		if entryPfx.Bits() == entryPfx.Addr().BitLen() {
			return entryPfx.Addr().Unmap() == *m.addr // single-host prefix
		}
		if m.contains {
			return entryPfx.Contains(*m.addr)
		}
	}
	return false
}

func (m Matcher) matchPrefix(e model.Entry) bool {
	if strings.EqualFold(e.Value, m.prefix.String()) {
		return true
	}
	if !m.contains {
		return false
	}
	if entryAddr, err := netip.ParseAddr(e.Value); err == nil {
		return m.prefix.Contains(entryAddr.Unmap())
	}
	if entryPfx, err := netip.ParsePrefix(e.Value); err == nil {
		entryPfx = entryPfx.Masked()
		return m.prefix.Contains(entryPfx.Addr()) || entryPfx.Contains(m.prefix.Addr())
	}
	return false
}

func globToRegexp(glob string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("(?i)^")
	for _, r := range glob {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// Resolver resolves hostnames to IP addresses.
type Resolver struct {
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
}

// New returns a Resolver backed by the system resolver.
func New() *Resolver {
	return &Resolver{lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}}
}

// Hostname resolves host to its A/AAAA addresses (deduplicated, IPv4-unmapped).
func (r *Resolver) Hostname(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := r.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	seen := make(map[netip.Addr]bool, len(addrs))
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		a = a.Unmap()
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out, nil
}
