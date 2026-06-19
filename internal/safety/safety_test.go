// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package safety

import (
	"net/netip"
	"testing"
)

func TestIntersects(t *testing.T) {
	set := []netip.Prefix{
		netip.MustParsePrefix("203.0.113.7/32"),
		netip.MustParsePrefix("10.0.0.0/8"),
	}
	for _, tc := range []struct {
		value string
		hit   bool
	}{
		{"203.0.113.7", true},
		{"203.0.113.8", false},
		{"10.1.2.3", true},
		{"10.0.0.0/16", true}, // overlaps the /8
		{"192.168.0.0/16", false},
	} {
		hit, _, err := intersects(set, tc.value)
		if err != nil {
			t.Fatalf("intersects(%q): %v", tc.value, err)
		}
		if hit != tc.hit {
			t.Errorf("intersects(%q) = %v, want %v", tc.value, hit, tc.hit)
		}
	}
}

func TestSSHClientPrefixes(t *testing.T) {
	p := sshClientPrefixes("203.0.113.9 51000 198.51.100.2 22", "")
	if len(p) != 1 || p[0].String() != "203.0.113.9/32" {
		t.Fatalf("SSH_CONNECTION parse = %v", p)
	}
	p = sshClientPrefixes("", "2001:db8::5 51000 22")
	if len(p) != 1 || p[0].String() != "2001:db8::5/128" {
		t.Fatalf("SSH_CLIENT parse = %v", p)
	}
	if len(sshClientPrefixes("", "")) != 0 {
		t.Fatal("empty SSH env should yield no prefixes")
	}
}

func TestGuardIsProtected(t *testing.T) {
	env := func(k string) string {
		if k == "SSH_CONNECTION" {
			return "203.0.113.9 51000 198.51.100.2 22"
		}
		return ""
	}
	g := Build([]string{"192.168.50.0/24"}, env)

	if ok, _ := g.IsProtected("203.0.113.9"); !ok {
		t.Fatal("SSH client IP must be protected")
	}
	if ok, _ := g.IsProtected("127.0.0.1"); !ok {
		t.Fatal("loopback must be protected")
	}
	if ok, _ := g.IsProtected("192.168.50.10"); !ok {
		t.Fatal("admin allowlist CIDR must be protected")
	}
	if ok, _ := g.IsProtected("198.51.100.50"); ok {
		t.Fatal("unrelated IP must not be protected")
	}
}

func TestJournalPushPop(t *testing.T) {
	j := NewJournal(t.TempDir())

	if _, ok, _ := j.Pop(); ok {
		t.Fatal("empty journal should pop nothing")
	}

	_ = j.Push(UndoRecord{InverseOp: "unban", Backend: "ufw", Value: "1.1.1.1"})
	_ = j.Push(UndoRecord{InverseOp: "unban", Backend: "csf", Value: "2.2.2.2"})

	rec, ok, err := j.Pop()
	if err != nil || !ok {
		t.Fatalf("pop: ok=%v err=%v", ok, err)
	}
	if rec.Value != "2.2.2.2" || rec.Backend != "csf" {
		t.Fatalf("LIFO order wrong: %+v", rec)
	}
	rec, ok, _ = j.Pop()
	if !ok || rec.Value != "1.1.1.1" {
		t.Fatalf("second pop wrong: %+v", rec)
	}
	if _, ok, _ := j.Pop(); ok {
		t.Fatal("journal should now be empty")
	}
}

func TestNilJournalNoop(t *testing.T) {
	var j *Journal
	if err := j.Push(UndoRecord{}); err != nil {
		t.Fatalf("nil journal push: %v", err)
	}
	if _, ok, err := j.Pop(); ok || err != nil {
		t.Fatalf("nil journal pop: ok=%v err=%v", ok, err)
	}
}
