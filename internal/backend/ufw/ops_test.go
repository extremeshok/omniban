// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package ufw

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

func fixture(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "status_numbered.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// fakeWithStatus returns a FakeRunner primed with the golden status output.
func fakeWithStatus(t *testing.T) *exec.FakeRunner {
	f := exec.NewFake()
	f.Set(fixture(t), 0, "ufw", "status", "numbered")
	return f
}

func TestListBansFixture(t *testing.T) {
	entries, err := New(fakeWithStatus(t)).ListBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("want 4 bans, got %d: %+v", len(entries), entries)
	}

	e := entries[0]
	if e.Value != "1.2.3.4" || e.Family != model.FamilyIPv4 || e.Scope != model.ScopeIP {
		t.Fatalf("entry[0] = %+v", e)
	}
	if e.Kind != model.KindBan || e.Direction != model.DirInbound {
		t.Fatalf("entry[0] kind/direction = %+v", e)
	}
	if e.Origin != model.OriginUFW || e.Backend != string(model.OriginUFW) {
		t.Fatalf("entry[0] attribution = %+v", e)
	}

	// REJECT also maps to a ban.
	if entries[1].Value != "198.51.100.7" || entries[1].Kind != model.KindBan {
		t.Fatalf("entry[1] = %+v", entries[1])
	}
	// IPv6 host.
	if entries[2].Value != "2001:db8::1" || entries[2].Family != model.FamilyIPv6 {
		t.Fatalf("entry[2] = %+v", entries[2])
	}
	// IPv4 CIDR -> range scope.
	if entries[3].Value != "203.0.113.0/24" || entries[3].Scope != model.ScopeRange {
		t.Fatalf("entry[3] = %+v", entries[3])
	}
}

func TestListAllowsFixture(t *testing.T) {
	entries, err := New(fakeWithStatus(t)).ListAllows(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 allows, got %d: %+v", len(entries), entries)
	}
	for i, e := range entries {
		if e.Kind != model.KindAllow {
			t.Fatalf("entry[%d] kind = %v", i, e.Kind)
		}
		if e.Origin != model.OriginUFW || e.Backend != string(model.OriginUFW) {
			t.Fatalf("entry[%d] attribution = %+v", i, e)
		}
	}
	// IPv4 CIDR allow.
	if entries[0].Value != "10.0.0.0/8" || entries[0].Scope != model.ScopeRange ||
		entries[0].Family != model.FamilyIPv4 {
		t.Fatalf("entry[0] = %+v", entries[0])
	}
	// IPv6 CIDR allow.
	if entries[1].Value != "2001:db8:abcd::/48" || entries[1].Family != model.FamilyIPv6 ||
		entries[1].Scope != model.ScopeRange {
		t.Fatalf("entry[1] = %+v", entries[1])
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
	want := "ufw deny from 5.6.7.8"
	if len(res.Commands) != 1 || res.Commands[0] != want {
		t.Fatalf("commands = %v, want %q", res.Commands, want)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

func TestAllowDryRun(t *testing.T) {
	f := exec.NewFake()
	res, err := New(f).Allow(context.Background(), model.ActionRequest{
		Value: "192.0.2.10", Reason: "office", DryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Commands) != 1 || res.Commands[0] != "ufw allow from 192.0.2.10" {
		t.Fatalf("allow command = %v", res.Commands)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

func TestUnbanExecutes(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "ufw", "delete", "deny", "from", "1.2.3.4")
	res, err := New(f).Unban(context.Background(), model.Entry{Value: "1.2.3.4"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("executed unban should report a change")
	}
	if res.DryRun {
		t.Fatal("executed unban must not be flagged dry-run")
	}
	if len(res.Commands) != 1 || res.Commands[0] != "ufw delete deny from 1.2.3.4" {
		t.Fatalf("unban command = %v", res.Commands)
	}
	if len(f.Calls) != 1 || f.Calls[0] != "ufw delete deny from 1.2.3.4" {
		t.Fatalf("runner calls = %v", f.Calls)
	}
}

func TestRemoveAllowExecutes(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "ufw", "delete", "allow", "from", "10.0.0.0/8")
	res, err := New(f).RemoveAllow(context.Background(), model.Entry{Value: "10.0.0.0/8"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("executed remove-allow should report a change")
	}
	if len(f.Calls) != 1 || f.Calls[0] != "ufw delete allow from 10.0.0.0/8" {
		t.Fatalf("runner calls = %v", f.Calls)
	}
}

func TestBanExecutes(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "ufw", "deny", "from", "9.9.9.9")
	res, err := New(f).Ban(context.Background(), model.ActionRequest{Value: "9.9.9.9", Scope: model.ScopeIP})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("executed ban should report a change")
	}
	if len(f.Calls) != 1 || f.Calls[0] != "ufw deny from 9.9.9.9" {
		t.Fatalf("runner calls = %v", f.Calls)
	}
}
