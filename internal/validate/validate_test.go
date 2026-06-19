// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package validate

import "testing"

func TestIP(t *testing.T) {
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{"1.2.3.4", true},
		{"2001:db8::1", true},
		{"::ffff:1.2.3.4", true}, // IPv4-mapped, normalized via Unmap
		{"1.2.3.4/32", false},
		{"not-an-ip", false},
		{"", false},
	} {
		_, err := IP(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("IP(%q): ok=%v err=%v", tc.in, tc.ok, err)
		}
	}
}

func TestIPOrCIDR(t *testing.T) {
	p, single, err := IPOrCIDR("10.0.0.5")
	if err != nil || !single || p.Bits() != 32 {
		t.Fatalf("IPOrCIDR single: p=%v single=%v err=%v", p, single, err)
	}
	p, single, err = IPOrCIDR("10.0.0.0/8")
	if err != nil || single || p.String() != "10.0.0.0/8" {
		t.Fatalf("IPOrCIDR cidr: p=%v single=%v err=%v", p, single, err)
	}
	if _, _, err := IPOrCIDR("nope"); err == nil {
		t.Fatal("IPOrCIDR(nope) should error")
	}
}

func TestCIDRMasked(t *testing.T) {
	p, err := CIDR("10.1.2.3/8")
	if err != nil {
		t.Fatal(err)
	}
	if p.String() != "10.0.0.0/8" {
		t.Fatalf("CIDR not masked: %s", p)
	}
}

func TestHostnameAndDomain(t *testing.T) {
	for _, tc := range []struct {
		in     string
		host   bool
		domain bool
	}{
		{"example.com", true, true},
		{"sub.example.com.", true, true},
		{"localhost", true, false}, // valid host label, but not a FQDN
		{"1.2.3.4", false, false},  // IP literal is not a hostname
		{"-bad.example.com", false, false},
		{"", false, false},
	} {
		if got := Hostname(tc.in) == nil; got != tc.host {
			t.Errorf("Hostname(%q)=%v want %v", tc.in, got, tc.host)
		}
		if got := Domain(tc.in) == nil; got != tc.domain {
			t.Errorf("Domain(%q)=%v want %v", tc.in, got, tc.domain)
		}
	}
}

func TestDuration(t *testing.T) {
	if d, err := Duration(""); err != nil || d != 0 {
		t.Fatalf("empty duration: %v %v", d, err)
	}
	if _, err := Duration("4h"); err != nil {
		t.Fatalf("4h: %v", err)
	}
	if _, err := Duration("-1h"); err == nil {
		t.Fatal("negative duration should error")
	}
	if _, err := Duration("banana"); err == nil {
		t.Fatal("garbage duration should error")
	}
}
