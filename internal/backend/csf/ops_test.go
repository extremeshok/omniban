// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package csf

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// newFromTestdata returns a CSF adapter whose file paths point at the golden
// fixtures under testdata/.
func newFromTestdata(r exec.Runner) *Backend {
	b := New(r)
	b.denyFile = filepath.Join("testdata", "csf.deny")
	b.allowFile = filepath.Join("testdata", "csf.allow")
	b.ignoreFile = filepath.Join("testdata", "csf.ignore")
	return b
}

func TestListBansFixture(t *testing.T) {
	b := newFromTestdata(exec.NewFake())
	entries, err := b.ListBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Fatalf("want 5 bans, got %d: %+v", len(entries), entries)
	}

	e := entries[0]
	if e.Value != "1.2.3.4" || e.Family != model.FamilyIPv4 || e.Scope != model.ScopeIP {
		t.Fatalf("entry[0] = %+v", e)
	}
	if e.Kind != model.KindBan || e.Direction != model.DirInbound {
		t.Fatalf("entry[0] kind/direction = %+v", e)
	}
	if e.Origin != model.OriginCSF || e.Backend != string(model.OriginCSF) {
		t.Fatalf("entry[0] attribution = %+v", e)
	}
	if e.Detail != "# lfd: (sshd) Failed SSH login from 1.2.3.4: 2024-01-02 03:04:05" {
		t.Fatalf("entry[0] detail = %q", e.Detail)
	}

	if entries[2].Scope != model.ScopeRange || entries[2].Value != "10.0.0.0/24" {
		t.Fatalf("entry[2] = %+v", entries[2])
	}
	if entries[3].Family != model.FamilyIPv6 || entries[3].Value != "2001:db8::1" {
		t.Fatalf("entry[3] = %+v", entries[3])
	}
	// Bare IP with no trailing comment carries an empty detail.
	if entries[4].Value != "198.51.100.7" || entries[4].Detail != "" {
		t.Fatalf("entry[4] = %+v", entries[4])
	}
}

func TestListAllowsFixture(t *testing.T) {
	b := newFromTestdata(exec.NewFake())
	entries, err := b.ListAllows(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// 3 from csf.allow + 1 from csf.ignore.
	if len(entries) != 4 {
		t.Fatalf("want 4 allows, got %d: %+v", len(entries), entries)
	}
	for i, e := range entries {
		if e.Kind != model.KindAllow {
			t.Fatalf("entry[%d] kind = %v", i, e.Kind)
		}
		if e.Origin != model.OriginCSF || e.Backend != string(model.OriginCSF) {
			t.Fatalf("entry[%d] attribution = %+v", i, e)
		}
	}
	if entries[1].Scope != model.ScopeRange || entries[1].Value != "203.0.113.0/24" {
		t.Fatalf("entry[1] = %+v", entries[1])
	}
	if entries[2].Family != model.FamilyIPv6 {
		t.Fatalf("entry[2] family = %v", entries[2].Family)
	}
	// The csf.ignore entry is tagged with detail "ignore".
	ign := entries[3]
	if ign.Value != "192.0.2.250" || ign.Detail != "ignore" {
		t.Fatalf("ignore entry = %+v", ign)
	}
}

func TestListBansMissingFile(t *testing.T) {
	b := New(exec.NewFake())
	b.denyFile = filepath.Join(t.TempDir(), "absent.deny")
	entries, err := b.ListBans(context.Background())
	if err != nil {
		t.Fatalf("missing file should be empty, not error: %v", err)
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
	want := "csf -d 5.6.7.8 omniban: bruteforce"
	if len(res.Commands) != 1 || res.Commands[0] != want {
		t.Fatalf("commands = %v, want %q", res.Commands, want)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

func TestBanTemporaryDryRun(t *testing.T) {
	f := exec.NewFake()
	res, err := New(f).Ban(context.Background(), model.ActionRequest{
		Value: "5.6.7.8", Scope: model.ScopeIP, Reason: "temp", Duration: 2 * time.Hour, DryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "csf -td 5.6.7.8 7200 omniban: temp"
	if len(res.Commands) != 1 || res.Commands[0] != want {
		t.Fatalf("commands = %v, want %q", res.Commands, want)
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
	if len(res.Commands) != 1 || res.Commands[0] != "csf -dr 1.2.3.4" {
		t.Fatalf("unban command = %v", res.Commands)
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
	if len(res.Commands) != 1 || res.Commands[0] != "csf -a 192.0.2.10 omniban: office" {
		t.Fatalf("allow command = %v", res.Commands)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

func TestRemoveAllowDryRun(t *testing.T) {
	f := exec.NewFake()
	res, err := New(f).RemoveAllow(context.Background(), model.Entry{Value: "192.0.2.10"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Commands) != 1 || res.Commands[0] != "csf -ar 192.0.2.10" {
		t.Fatalf("remove-allow command = %v", res.Commands)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

func TestUnbanExecutes(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "csf", "-dr", "1.2.3.4")
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
	if len(f.Calls) != 1 || f.Calls[0] != "csf -dr 1.2.3.4" {
		t.Fatalf("runner calls = %v", f.Calls)
	}
}

func TestBanExecutes(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "csf", "-d", "9.9.9.9", "omniban: ")
	res, err := New(f).Ban(context.Background(), model.ActionRequest{Value: "9.9.9.9", Scope: model.ScopeIP})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("executed ban should report a change")
	}
	if len(f.Calls) != 1 || f.Calls[0] != "csf -d 9.9.9.9 omniban: " {
		t.Fatalf("runner calls = %v", f.Calls)
	}
}
