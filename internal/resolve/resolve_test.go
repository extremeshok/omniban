// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package resolve

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/extremeshok/omniban/internal/model"
)

func ban(value string) model.Entry { return model.Entry{Value: value, Kind: model.KindBan} }

func TestMatchExactIP(t *testing.T) {
	m := NewMatcher("1.2.3.4", false)
	if !m.Matches(ban("1.2.3.4")) {
		t.Fatal("exact IP should match")
	}
	if m.Matches(ban("1.2.3.5")) {
		t.Fatal("different IP should not match")
	}
	if m.Matches(ban("1.2.3.0/24")) {
		t.Fatal("CIDR should not match without --contains")
	}
}

func TestMatchCIDRContains(t *testing.T) {
	m := NewMatcher("1.2.3.4", true)
	if !m.Matches(ban("1.2.3.0/24")) {
		t.Fatal("IP should match covering CIDR with --contains")
	}
	if m.Matches(ban("1.2.4.0/24")) {
		t.Fatal("IP outside CIDR should not match")
	}
}

func TestMatchCIDRQuery(t *testing.T) {
	m := NewMatcher("10.0.0.0/8", true)
	if !m.Matches(ban("10.1.2.3")) {
		t.Fatal("IP inside query CIDR should match with --contains")
	}
	if !m.Matches(ban("10.0.0.0/8")) {
		t.Fatal("identical CIDR should match")
	}
	if m.Matches(ban("192.168.0.1")) {
		t.Fatal("IP outside query CIDR should not match")
	}
}

func TestMatchGlob(t *testing.T) {
	m := NewMatcher("192.168.1.*", false)
	if !m.Matches(ban("192.168.1.55")) {
		t.Fatal("glob should match")
	}
	if m.Matches(ban("192.168.2.55")) {
		t.Fatal("glob should not match other subnet")
	}

	hostGlob := NewMatcher("*.evil.com", false)
	e := model.Entry{Value: "0.0.0.0", Hostname: "ads.evil.com", Scope: model.ScopeDomain}
	if !hostGlob.Matches(e) {
		t.Fatal("glob should match hostname field")
	}
}

func TestMatchDomain(t *testing.T) {
	m := NewMatcher("evil.com", false)
	if !m.Matches(model.Entry{Value: "evil.com", Scope: model.ScopeDomain}) {
		t.Fatal("domain should match by value")
	}
	if !m.Matches(model.Entry{Value: "0.0.0.0", Hostname: "EVIL.COM"}) {
		t.Fatal("domain should match hostname case-insensitively")
	}
}

func TestResolverHostname(t *testing.T) {
	r := &Resolver{lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != "example.test" {
			return nil, errors.New("nxdomain")
		}
		return []netip.Addr{
			netip.MustParseAddr("203.0.113.10"),
			netip.MustParseAddr("203.0.113.10"), // duplicate, must be collapsed
			netip.MustParseAddr("2001:db8::1"),
		}, nil
	}}
	addrs, err := r.Hostname(context.Background(), "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 2 {
		t.Fatalf("want 2 deduped addrs, got %v", addrs)
	}
}
