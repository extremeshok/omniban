// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package nftables

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// loadRuleset returns the golden `nft -j list ruleset` fixture.
func loadRuleset(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "ruleset.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return string(data)
}

func TestListBansFixture(t *testing.T) {
	f := exec.NewFake()
	f.Set(loadRuleset(t), 0, "nft", "-j", "list", "ruleset")

	entries, err := New(f).ListBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Only omniban's own deny4 (2) + deny6 (1) elements; the foreign
	// firewalld set must be ignored.
	if len(entries) != 3 {
		t.Fatalf("want 3 bans, got %d: %+v", len(entries), entries)
	}

	e := entries[0]
	if e.Value != "1.2.3.4" || e.Family != model.FamilyIPv4 || e.Scope != model.ScopeIP {
		t.Fatalf("entry[0] = %+v", e)
	}
	if e.Kind != model.KindBan || e.Direction != model.DirInbound {
		t.Fatalf("entry[0] kind/direction = %+v", e)
	}
	if e.Origin != model.OriginNftables || e.Backend != string(model.OriginNftables) {
		t.Fatalf("entry[0] attribution = %+v", e)
	}

	// The prefix element decodes to addr/len with range scope.
	if entries[1].Value != "10.0.0.0/8" || entries[1].Scope != model.ScopeRange {
		t.Fatalf("entry[1] = %+v", entries[1])
	}
	if entries[1].Family != model.FamilyIPv4 {
		t.Fatalf("entry[1] family = %v", entries[1].Family)
	}

	// The deny6 member.
	if entries[2].Value != "2001:db8::1" || entries[2].Family != model.FamilyIPv6 {
		t.Fatalf("entry[2] = %+v", entries[2])
	}

	for _, e := range entries {
		if e.Value == "203.0.113.99" {
			t.Fatalf("foreign firewalld element leaked into results: %+v", entries)
		}
	}
}

func TestListBansMissingTable(t *testing.T) {
	f := exec.NewFake()
	// No canned response => Run errors; ListBans must tolerate it.
	entries, err := New(f).ListBans(context.Background())
	if err != nil {
		t.Fatalf("missing ruleset should be empty, not error: %v", err)
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
	want := "nft add element inet omniban deny4 { 5.6.7.8 }"
	if len(res.Commands) != 1 || res.Commands[0] != want {
		t.Fatalf("commands = %v, want %q", res.Commands, want)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

func TestBanIPv6DryRun(t *testing.T) {
	f := exec.NewFake()
	res, err := New(f).Ban(context.Background(), model.ActionRequest{
		Value: "2001:db8::5", Scope: model.ScopeIP, DryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "nft add element inet omniban deny6 { 2001:db8::5 }"
	if len(res.Commands) != 1 || res.Commands[0] != want {
		t.Fatalf("commands = %v, want %q", res.Commands, want)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

// TestBanExecutesScaffoldPresent verifies that when the owned table already
// exists, Ban probes once and then issues only the add-element command.
func TestBanExecutesScaffoldPresent(t *testing.T) {
	f := exec.NewFake()
	// Probe succeeds => scaffold present.
	f.Set("table inet omniban {\n}\n", 0, "nft", "list", "table", "inet", "omniban")
	f.Set("", 0, "nft", "add", "element", "inet", "omniban", "deny4", "{", "9.9.9.9", "}")

	res, err := New(f).Ban(context.Background(), model.ActionRequest{Value: "9.9.9.9", Scope: model.ScopeIP})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.DryRun {
		t.Fatalf("executed ban flags = %+v", res)
	}
	wantCalls := []string{
		"nft list table inet omniban",
		"nft add element inet omniban deny4 { 9.9.9.9 }",
	}
	if len(f.Calls) != len(wantCalls) {
		t.Fatalf("runner calls = %v, want %v", f.Calls, wantCalls)
	}
	for i, c := range wantCalls {
		if f.Calls[i] != c {
			t.Fatalf("call[%d] = %q, want %q", i, f.Calls[i], c)
		}
	}
}

// TestBanExecutesScaffoldCreated verifies the idempotent scaffold is built (in
// order) when the owned table is absent, then the element is added.
func TestBanExecutesScaffoldCreated(t *testing.T) {
	f := exec.NewFake()
	// Probe fails (exit 1) => table absent; scaffold must be created.
	f.Set("", 1, "nft", "list", "table", "inet", "omniban")
	f.Set("", 0, "nft", "add", "table", "inet", "omniban")
	f.Set("", 0, "nft", "add", "set", "inet", "omniban", "deny4", "{ type ipv4_addr ; flags interval ; }")
	f.Set("", 0, "nft", "add", "set", "inet", "omniban", "deny6", "{ type ipv6_addr ; flags interval ; }")
	f.Set("", 0, "nft", "add", "chain", "inet", "omniban", "input", "{ type filter hook input priority 0 ; policy accept ; }")
	f.Set("", 0, "nft", "add", "rule", "inet", "omniban", "input", "ip", "saddr", "@deny4", "drop")
	f.Set("", 0, "nft", "add", "rule", "inet", "omniban", "input", "ip6", "saddr", "@deny6", "drop")
	f.Set("", 0, "nft", "add", "element", "inet", "omniban", "deny4", "{", "9.9.9.9", "}")

	res, err := New(f).Ban(context.Background(), model.ActionRequest{Value: "9.9.9.9", Scope: model.ScopeIP})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("executed ban should report a change")
	}
	wantCalls := []string{
		"nft list table inet omniban",
		"nft add table inet omniban",
		"nft add set inet omniban deny4 { type ipv4_addr ; flags interval ; }",
		"nft add set inet omniban deny6 { type ipv6_addr ; flags interval ; }",
		"nft add chain inet omniban input { type filter hook input priority 0 ; policy accept ; }",
		"nft add rule inet omniban input ip saddr @deny4 drop",
		"nft add rule inet omniban input ip6 saddr @deny6 drop",
		"nft add element inet omniban deny4 { 9.9.9.9 }",
	}
	if len(f.Calls) != len(wantCalls) {
		t.Fatalf("runner calls = %v, want %v", f.Calls, wantCalls)
	}
	for i, c := range wantCalls {
		if f.Calls[i] != c {
			t.Fatalf("call[%d] = %q, want %q", i, f.Calls[i], c)
		}
	}
}

func TestUnbanDryRun(t *testing.T) {
	f := exec.NewFake()
	res, err := New(f).Unban(context.Background(), model.Entry{Value: "1.2.3.4"}, true)
	if err != nil {
		t.Fatal(err)
	}
	want := "nft delete element inet omniban deny4 { 1.2.3.4 }"
	if len(res.Commands) != 1 || res.Commands[0] != want {
		t.Fatalf("unban command = %v, want %q", res.Commands, want)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

func TestUnbanIPv6Executes(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "nft", "delete", "element", "inet", "omniban", "deny6", "{", "2001:db8::1", "}")
	res, err := New(f).Unban(context.Background(), model.Entry{Value: "2001:db8::1"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.DryRun {
		t.Fatalf("executed unban flags = %+v", res)
	}
	if len(f.Calls) != 1 || f.Calls[0] != "nft delete element inet omniban deny6 { 2001:db8::1 }" {
		t.Fatalf("runner calls = %v", f.Calls)
	}
}

func TestReloadPersistsTable(t *testing.T) {
	dir := t.TempDir()
	orig := persistPath
	persistPath = filepath.Join(dir, "sub", "nftables.nft")
	defer func() { persistPath = orig }()

	f := exec.NewFake()
	f.Set("table inet omniban {\n\tset deny4 {\n\t}\n}", 0, "nft", "list", "table", "inet", "omniban")

	if err := New(f).Reload(context.Background()); err != nil {
		t.Fatalf("reload: %v", err)
	}
	data, err := os.ReadFile(persistPath)
	if err != nil {
		t.Fatalf("read persisted snapshot: %v", err)
	}
	if len(data) == 0 || !strings.Contains(string(data), "table inet omniban") {
		t.Fatalf("persisted snapshot = %q", data)
	}
}

func TestReloadMissingTableNoError(t *testing.T) {
	f := exec.NewFake() // no canned response => probe errors
	if err := New(f).Reload(context.Background()); err != nil {
		t.Fatalf("reload with no table should be a best-effort no-op: %v", err)
	}
}
