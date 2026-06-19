// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package blackhole

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

func TestListBans(t *testing.T) {
	f := exec.NewFake()
	f.Set("blackhole 203.0.113.0/24\nblackhole 198.51.100.7", 0, "ip", "route", "show", "type", "blackhole")
	f.Set("blackhole 2001:db8::/48", 0, "ip", "-6", "route", "show", "type", "blackhole")

	entries, err := New(f).ListBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("want 3 blackhole routes, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Direction != model.DirBoth || e.Origin != model.OriginBlackhole {
			t.Fatalf("bad attribution: %+v", e)
		}
	}
	if entries[0].Scope != model.ScopeRange || entries[2].Family != model.FamilyIPv6 {
		t.Fatalf("scope/family wrong: %+v", entries)
	}
}

func TestBanDryRun(t *testing.T) {
	f := exec.NewFake()
	res, err := New(f).Ban(context.Background(), model.ActionRequest{Value: "203.0.113.0/24", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed || len(f.Calls) != 0 {
		t.Fatalf("dry-run must not execute: changed=%v calls=%v", res.Changed, f.Calls)
	}
	if res.Commands[0] != "ip route add blackhole 203.0.113.0/24" {
		t.Fatalf("command = %q", res.Commands[0])
	}
}

func TestBanExecutesAndPersists(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "ip", "route", "add", "blackhole", "5.6.7.8")
	b := New(f)
	b.routesFile = filepath.Join(t.TempDir(), "routes.conf")

	res, err := b.Ban(context.Background(), model.ActionRequest{Value: "5.6.7.8"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("ban should report a change")
	}
	data, _ := os.ReadFile(b.routesFile)
	if !strings.Contains(string(data), "5.6.7.8") {
		t.Fatalf("route not persisted: %q", data)
	}
}

func TestApplyReplaysPersisted(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "ip", "route", "add", "blackhole", "203.0.113.0/24")
	f.Set("", 0, "ip", "-6", "route", "add", "blackhole", "2001:db8::/48")
	b := New(f)
	b.routesFile = filepath.Join(t.TempDir(), "routes.conf")
	if err := os.WriteFile(b.routesFile, []byte("203.0.113.0/24\n2001:db8::/48\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := b.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.Calls) != 2 {
		t.Fatalf("Apply should replay 2 routes, got calls %v", f.Calls)
	}
}
