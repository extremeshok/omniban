// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

// Package validate gates every user-controlled string that reaches a path,
// shell-adjacent position, or external command argument. Validators return a
// normalized value (or a descriptive error) and never panic on hostile input.
package validate

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// IP parses and normalizes a bare IPv4/IPv6 address.
func IP(s string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid IP address %q", s)
	}
	return addr.Unmap(), nil
}

// CIDR parses and normalizes a CIDR prefix (the address is masked to the prefix).
func CIDR(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", s)
	}
	return p.Masked(), nil
}

// IPOrCIDR accepts either form and reports the prefix plus whether it was a
// single address (a /32 or /128).
func IPOrCIDR(s string) (netip.Prefix, bool, error) {
	s = strings.TrimSpace(s)
	if addr, err := netip.ParseAddr(s); err == nil {
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), true, nil
	}
	p, err := CIDR(s)
	if err != nil {
		return netip.Prefix{}, false, fmt.Errorf("invalid IP or CIDR %q", s)
	}
	return p, p.Bits() == p.Addr().BitLen(), nil
}

// Hostname validates an RFC 1123 host label sequence (the kind that resolves
// via DNS). It rejects anything that is actually an IP literal.
func Hostname(s string) error {
	s = strings.TrimSpace(strings.TrimSuffix(s, "."))
	if s == "" || len(s) > 253 {
		return fmt.Errorf("invalid hostname %q", s)
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return fmt.Errorf("%q is an IP address, not a hostname", s)
	}
	for _, label := range strings.Split(s, ".") {
		if !validLabel(label) {
			return fmt.Errorf("invalid hostname %q", s)
		}
	}
	return nil
}

// Domain is an alias for Hostname that additionally requires at least one dot,
// rejecting bare single labels for domain-sinkhole operations.
func Domain(s string) error {
	if err := Hostname(s); err != nil {
		return err
	}
	if !strings.Contains(strings.TrimSuffix(strings.TrimSpace(s), "."), ".") {
		return fmt.Errorf("%q is not a fully qualified domain", s)
	}
	return nil
}

func validLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, r := range label {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// Duration parses a Go duration; it accepts the empty string as "permanent"
// (zero duration). Negative durations are rejected.
func Duration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q (use forms like 30m, 4h, 7d→168h)", s)
	}
	if d < 0 {
		return 0, fmt.Errorf("duration %q must not be negative", s)
	}
	return d, nil
}
