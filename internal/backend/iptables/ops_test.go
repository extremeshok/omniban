// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package iptables

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/extremeshok/omniban/internal/config"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// readFixture loads a golden file from testdata/.
func readFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(data)
}

func TestListBansFixture(t *testing.T) {
	f := exec.NewFake()
	f.Set(readFixture(t, "save_v4.txt"), 0, "iptables", "-S", config.IptablesChainIn)
	f.Set(readFixture(t, "save_v6.txt"), 0, "ip6tables", "-S", config.IptablesChainIn)

	entries, err := New(f).ListBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("want 4 bans, got %d: %+v", len(entries), entries)
	}

	// IPv4 host: the /32 collapses to a bare IP, scope ip.
	e := entries[0]
	if e.Value != "1.2.3.4" || e.Family != model.FamilyIPv4 || e.Scope != model.ScopeIP {
		t.Fatalf("entry[0] = %+v", e)
	}
	if e.Kind != model.KindBan || e.Direction != model.DirInbound {
		t.Fatalf("entry[0] kind/direction = %+v", e)
	}
	if e.Origin != model.OriginIptables || e.Backend != string(model.OriginIptables) {
		t.Fatalf("entry[0] attribution = %+v", e)
	}

	// IPv4 range keeps its CIDR, scope range.
	if entries[1].Value != "10.0.0.0/24" || entries[1].Scope != model.ScopeRange {
		t.Fatalf("entry[1] = %+v", entries[1])
	}

	// IPv6 host: the /128 collapses to a bare IP, scope ip, family ipv6.
	if entries[2].Value != "2001:db8::1" || entries[2].Family != model.FamilyIPv6 || entries[2].Scope != model.ScopeIP {
		t.Fatalf("entry[2] = %+v", entries[2])
	}

	// IPv6 range keeps its CIDR.
	if entries[3].Value != "2001:db8:dead::/48" || entries[3].Scope != model.ScopeRange {
		t.Fatalf("entry[3] = %+v", entries[3])
	}
}

func TestListBansMissingChain(t *testing.T) {
	f := exec.NewFake()
	// A non-existent chain exits non-zero for both families.
	f.Set("", 1, "iptables", "-S", config.IptablesChainIn)
	f.Set("", 1, "ip6tables", "-S", config.IptablesChainIn)

	entries, err := New(f).ListBans(context.Background())
	if err != nil {
		t.Fatalf("missing chain should be empty, not error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("want 0 entries, got %d", len(entries))
	}
}

func TestBanDryRun(t *testing.T) {
	f := exec.NewFake()
	res, err := New(f).Ban(context.Background(), model.ActionRequest{
		Value: "5.6.7.8", Scope: model.ScopeIP, Reason: "bruteforce", DryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("dry-run must not report a change")
	}
	if !res.DryRun || res.Message != "dry-run: not executed" {
		t.Fatalf("dry-run flags = %+v", res)
	}
	wantAdd := "iptables -A OMNIBAN_INPUT -s 5.6.7.8 -j DROP"
	last := res.Commands[len(res.Commands)-1]
	if last != wantAdd {
		t.Fatalf("final command = %q, want %q (all: %v)", last, wantAdd, res.Commands)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

func TestBanDryRunIPv6(t *testing.T) {
	f := exec.NewFake()
	res, err := New(f).Ban(context.Background(), model.ActionRequest{
		Value: "2001:db8::99", Scope: model.ScopeIP, DryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantAdd := "ip6tables -A OMNIBAN_INPUT -s 2001:db8::99 -j DROP"
	last := res.Commands[len(res.Commands)-1]
	if last != wantAdd {
		t.Fatalf("final command = %q, want %q (all: %v)", last, wantAdd, res.Commands)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

func TestBanExecutesChainPresent(t *testing.T) {
	f := exec.NewFake()
	// Chain already exists: -N exits non-zero (tolerated).
	f.Set("", 1, "iptables", "-N", config.IptablesChainIn)
	// Reference rule already present: -C succeeds, so -I is skipped.
	f.Set("", 0, "iptables", "-C", "INPUT", "-j", config.IptablesChainIn)
	f.Set("", 0, "iptables", "-A", config.IptablesChainIn, "-s", "9.9.9.9", "-j", "DROP")

	res, err := New(f).Ban(context.Background(), model.ActionRequest{Value: "9.9.9.9", Scope: model.ScopeIP})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("executed ban should report a change")
	}
	if res.DryRun {
		t.Fatal("executed ban must not be flagged dry-run")
	}
	want := []string{
		"iptables -N OMNIBAN_INPUT",
		"iptables -C INPUT -j OMNIBAN_INPUT",
		"iptables -A OMNIBAN_INPUT -s 9.9.9.9 -j DROP",
	}
	if len(f.Calls) != len(want) {
		t.Fatalf("runner calls = %v, want %v", f.Calls, want)
	}
	for i, w := range want {
		if f.Calls[i] != w {
			t.Fatalf("call[%d] = %q, want %q", i, f.Calls[i], w)
		}
	}
}

func TestBanExecutesChainMissing(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 1, "iptables", "-N", config.IptablesChainIn)
	// Reference rule absent: -C exits non-zero, so -I INPUT must run.
	f.Set("", 1, "iptables", "-C", "INPUT", "-j", config.IptablesChainIn)
	f.Set("", 0, "iptables", "-I", "INPUT", "-j", config.IptablesChainIn)
	f.Set("", 0, "iptables", "-A", config.IptablesChainIn, "-s", "9.9.9.9", "-j", "DROP")

	res, err := New(f).Ban(context.Background(), model.ActionRequest{Value: "9.9.9.9", Scope: model.ScopeIP})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("executed ban should report a change")
	}
	want := []string{
		"iptables -N OMNIBAN_INPUT",
		"iptables -C INPUT -j OMNIBAN_INPUT",
		"iptables -I INPUT -j OMNIBAN_INPUT",
		"iptables -A OMNIBAN_INPUT -s 9.9.9.9 -j DROP",
	}
	if len(f.Calls) != len(want) {
		t.Fatalf("runner calls = %v, want %v", f.Calls, want)
	}
	for i, w := range want {
		if f.Calls[i] != w {
			t.Fatalf("call[%d] = %q, want %q", i, f.Calls[i], w)
		}
	}
}

func TestUnbanDryRun(t *testing.T) {
	f := exec.NewFake()
	res, err := New(f).Unban(context.Background(), model.Entry{Value: "1.2.3.4"}, true)
	if err != nil {
		t.Fatal(err)
	}
	want := "iptables -D OMNIBAN_INPUT -s 1.2.3.4 -j DROP"
	if len(res.Commands) != 1 || res.Commands[0] != want {
		t.Fatalf("unban command = %v, want %q", res.Commands, want)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

func TestUnbanExecutesIPv6(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "ip6tables", "-D", config.IptablesChainIn, "-s", "2001:db8::1", "-j", "DROP")
	res, err := New(f).Unban(context.Background(), model.Entry{Value: "2001:db8::1"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("executed unban should report a change")
	}
	want := "ip6tables -D OMNIBAN_INPUT -s 2001:db8::1 -j DROP"
	if len(f.Calls) != 1 || f.Calls[0] != want {
		t.Fatalf("runner calls = %v, want %q", f.Calls, want)
	}
}
