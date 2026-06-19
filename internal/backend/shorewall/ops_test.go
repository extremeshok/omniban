// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package shorewall

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

func loadFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(data)
}

func TestListBansFixture(t *testing.T) {
	f := exec.NewFake()
	f.Set(loadFixture(t, "show-dynamic.txt"), 0, "shorewall", "show", "dynamic")

	entries, err := New(f).ListBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// 4 DROP/REJECT block lines; the trailing ACCEPT line is not a ban.
	if len(entries) != 4 {
		t.Fatalf("want 4 bans, got %d: %+v", len(entries), entries)
	}

	want := []struct {
		value  string
		family model.Family
		scope  model.Scope
		detail string
	}{
		{"1.2.3.4", model.FamilyIPv4, model.ScopeIP, "DROP"},
		{"10.0.0.0/24", model.FamilyIPv4, model.ScopeRange, "DROP"},
		{"198.51.100.7", model.FamilyIPv4, model.ScopeIP, "REJECT"},
		{"203.0.113.0/24", model.FamilyIPv4, model.ScopeRange, "DROP"},
	}
	for i, w := range want {
		e := entries[i]
		if e.Value != w.value || e.Family != w.family || e.Scope != w.scope || e.Detail != w.detail {
			t.Fatalf("entry[%d] = %+v, want value=%q family=%q scope=%q detail=%q",
				i, e, w.value, w.family, w.scope, w.detail)
		}
		if e.Kind != model.KindBan || e.Direction != model.DirInbound {
			t.Fatalf("entry[%d] kind/direction = %+v", i, e)
		}
		if e.Origin != model.OriginShorewall || e.Backend != string(model.OriginShorewall) {
			t.Fatalf("entry[%d] attribution = %+v", i, e)
		}
	}
}

func TestListBansEmpty(t *testing.T) {
	f := exec.NewFake()
	f.Set("Chain dynamic (1 references)\n pkts bytes target     prot opt in     out     source               destination\n", 0,
		"shorewall", "show", "dynamic")
	entries, err := New(f).ListBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("want 0 bans, got %d: %+v", len(entries), entries)
	}
}

func TestListBansMissingBinary(t *testing.T) {
	f := exec.NewFake()
	f.Missing = []string{"shorewall"}
	if _, err := New(f).ListBans(context.Background()); err == nil {
		t.Fatal("expected error when shorewall is absent")
	}
	if len(f.Calls) != 0 {
		t.Fatalf("must not invoke the runner when binary missing: %v", f.Calls)
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
	if len(res.Commands) != 1 || res.Commands[0] != "shorewall drop 5.6.7.8" {
		t.Fatalf("commands = %v", res.Commands)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

func TestUnbanDryRun(t *testing.T) {
	f := exec.NewFake()
	res, err := New(f).Unban(context.Background(), model.Entry{Value: "1.2.3.4"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Commands) != 1 || res.Commands[0] != "shorewall allow 1.2.3.4" {
		t.Fatalf("unban command = %v", res.Commands)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

func TestBanExecutes(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "shorewall", "drop", "9.9.9.9")
	res, err := New(f).Ban(context.Background(), model.ActionRequest{Value: "9.9.9.9", Scope: model.ScopeIP})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.DryRun {
		t.Fatalf("executed ban flags = %+v", res)
	}
	if len(f.Calls) != 1 || f.Calls[0] != "shorewall drop 9.9.9.9" {
		t.Fatalf("runner calls = %v", f.Calls)
	}
}

func TestUnbanExecutes(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "shorewall", "allow", "1.2.3.4")
	res, err := New(f).Unban(context.Background(), model.Entry{Value: "1.2.3.4"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.DryRun {
		t.Fatalf("executed unban flags = %+v", res)
	}
	if len(f.Calls) != 1 || f.Calls[0] != "shorewall allow 1.2.3.4" {
		t.Fatalf("runner calls = %v", f.Calls)
	}
}

func TestReloadSaves(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "shorewall", "save")
	if err := New(f).Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.Calls) != 1 || f.Calls[0] != "shorewall save" {
		t.Fatalf("reload calls = %v", f.Calls)
	}
}

func TestAllowUnsupported(t *testing.T) {
	f := exec.NewFake()
	if _, err := New(f).Allow(context.Background(), model.ActionRequest{Value: "1.2.3.4"}); err == nil {
		t.Fatal("Allow must be left to Unimplemented and return an error")
	}
	if _, err := New(f).RemoveAllow(context.Background(), model.Entry{Value: "1.2.3.4"}, false); err == nil {
		t.Fatal("RemoveAllow must be left to Unimplemented and return an error")
	}
}

func TestCapabilitiesTruthful(t *testing.T) {
	c := New(exec.NewFake()).Capabilities()
	if !c.CanBan || !c.CanUnban {
		t.Fatalf("ban/unban must be supported: %+v", c)
	}
	if c.CanAllow || c.CanRemoveAllow {
		t.Fatalf("allow/remove-allow must be false for the dynamic CLI: %+v", c)
	}
}
