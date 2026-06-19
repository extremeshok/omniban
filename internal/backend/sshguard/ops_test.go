// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package sshguard

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// tempWhitelist copies the testdata whitelist into a temp dir and returns a
// Backend pointing at the copy plus the copy's path.
func tempWhitelist(t *testing.T) (*Backend, string) {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("testdata", "whitelist"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "whitelist")
	if err := os.WriteFile(path, src, 0o644); err != nil {
		t.Fatal(err)
	}
	b := New(exec.NewFake())
	b.whitelist = path
	return b, path
}

func TestListAllowsParsesWhitelist(t *testing.T) {
	b, _ := tempWhitelist(t)
	entries, err := b.ListAllows(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("want 4 entries (comments skipped), got %d: %+v", len(entries), entries)
	}
	want := []struct {
		value  string
		family model.Family
		scope  model.Scope
	}{
		{"192.0.2.0/24", model.FamilyIPv4, model.ScopeRange},
		{"198.51.100.7", model.FamilyIPv4, model.ScopeIP},
		{"2001:db8::1", model.FamilyIPv6, model.ScopeIP},
		{"trusted.example.com", "", model.ScopeIP},
	}
	for i, w := range want {
		e := entries[i]
		if e.Value != w.value || e.Family != w.family || e.Scope != w.scope {
			t.Errorf("entry[%d] = %+v, want value=%q family=%q scope=%q", i, e, w.value, w.family, w.scope)
		}
		if e.Kind != model.KindAllow || e.Origin != model.OriginSSHGuard || e.Backend != "sshguard" {
			t.Errorf("entry[%d] attribution = %+v", i, e)
		}
		if e.Direction != model.DirInbound {
			t.Errorf("entry[%d] direction = %q", i, e.Direction)
		}
	}
}

func TestListAllowsMissingFile(t *testing.T) {
	b := New(exec.NewFake())
	b.whitelist = filepath.Join(t.TempDir(), "does-not-exist")
	entries, err := b.ListAllows(context.Background())
	if err != nil {
		t.Fatalf("missing whitelist must not error: %v", err)
	}
	if entries != nil {
		t.Fatalf("missing whitelist must yield no entries, got %+v", entries)
	}
}

func TestAllowDryRun(t *testing.T) {
	b, path := tempWhitelist(t)
	before, _ := os.ReadFile(path)

	res, err := b.Allow(context.Background(), model.ActionRequest{Value: "203.0.113.5", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("dry-run must not report a change")
	}
	if res.Message != "dry-run: not executed" {
		t.Fatalf("dry-run message = %q", res.Message)
	}
	if len(res.Commands) != 1 {
		t.Fatalf("dry-run commands = %v", res.Commands)
	}

	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("dry-run must not write the whitelist file")
	}
	if _, err := os.Stat(path + backupSuffix); !os.IsNotExist(err) {
		t.Fatal("dry-run must not create a backup")
	}
}

func TestAllowExecutesAndBacksUp(t *testing.T) {
	b, path := tempWhitelist(t)

	res, err := b.Allow(context.Background(), model.ActionRequest{Value: "203.0.113.5"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("executed allow should report a change")
	}

	// Backup exists and matches the pre-edit content.
	bak, err := os.ReadFile(path + backupSuffix)
	if err != nil {
		t.Fatalf("backup not created: %v", err)
	}
	orig, _ := os.ReadFile(filepath.Join("testdata", "whitelist"))
	if string(bak) != string(orig) {
		t.Fatal("backup content does not match original")
	}

	// New value present.
	entries, _ := b.ListAllows(context.Background())
	if !hasValue(entries, "203.0.113.5") {
		t.Fatalf("appended value missing: %+v", entries)
	}
}

func TestAllowIdempotent(t *testing.T) {
	b, path := tempWhitelist(t)

	res, err := b.Allow(context.Background(), model.ActionRequest{Value: "198.51.100.7"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("allowing an existing value must be a no-op")
	}
	if res.Message != "already present" {
		t.Fatalf("idempotent message = %q", res.Message)
	}
	// An untouched file means no backup either.
	if _, err := os.Stat(path + backupSuffix); !os.IsNotExist(err) {
		t.Fatal("no-op allow must not create a backup")
	}
}

func TestRemoveAllowExecutes(t *testing.T) {
	b, _ := tempWhitelist(t)

	res, err := b.RemoveAllow(context.Background(), model.Entry{Value: "198.51.100.7"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("removing an existing value should report a change")
	}
	entries, _ := b.ListAllows(context.Background())
	if hasValue(entries, "198.51.100.7") {
		t.Fatalf("value not removed: %+v", entries)
	}
}

func TestRemoveAllowDryRun(t *testing.T) {
	b, path := tempWhitelist(t)
	before, _ := os.ReadFile(path)

	res, err := b.RemoveAllow(context.Background(), model.Entry{Value: "198.51.100.7"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("dry-run must not report a change")
	}
	if len(res.Commands) != 1 {
		t.Fatalf("dry-run commands = %v", res.Commands)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("dry-run must not write the whitelist file")
	}
}

func TestRemoveAllowMissingValue(t *testing.T) {
	b, _ := tempWhitelist(t)
	res, err := b.RemoveAllow(context.Background(), model.Entry{Value: "9.9.9.9"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("removing an absent value must be a no-op")
	}
	if res.Message != "not present" {
		t.Fatalf("message = %q", res.Message)
	}
}

func TestParseRulesetFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "nft_ruleset.json"))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := parseRuleset(data)
	if err != nil {
		t.Fatal(err)
	}
	// Only the two sshguard tables contribute; the "filter" set is ignored.
	if len(entries) != 3 {
		t.Fatalf("want 3 sshguard elements, got %d: %+v", len(entries), entries)
	}
	want := map[string]struct {
		family model.Family
		scope  model.Scope
	}{
		"192.168.1.66":          {model.FamilyIPv4, model.ScopeIP},
		"10.20.0.0/24":          {model.FamilyIPv4, model.ScopeRange},
		"2001:db8:dead:beef::1": {model.FamilyIPv6, model.ScopeIP},
	}
	for _, e := range entries {
		w, ok := want[e.Value]
		if !ok {
			t.Errorf("unexpected element %q", e.Value)
			continue
		}
		if e.Family != w.family || e.Scope != w.scope {
			t.Errorf("%q = family %q scope %q, want %q/%q", e.Value, e.Family, e.Scope, w.family, w.scope)
		}
		if e.Kind != model.KindBan || e.Origin != model.OriginSSHGuard || e.Backend != "sshguard" {
			t.Errorf("%q attribution = %+v", e.Value, e)
		}
	}
}

func TestListBansViaRunner(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "nft_ruleset.json"))
	if err != nil {
		t.Fatal(err)
	}
	f := exec.NewFake()
	f.Set(string(data), 0, "nft", "-j", "list", "ruleset")
	b := New(f)
	entries, err := b.ListBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("ListBans = %d entries", len(entries))
	}
}

func TestListBansNftAbsent(t *testing.T) {
	f := exec.NewFake() // no canned response: Run returns an error
	b := New(f)
	entries, err := b.ListBans(context.Background())
	if err != nil {
		t.Fatalf("missing nft must not error: %v", err)
	}
	if entries != nil {
		t.Fatalf("missing nft must yield no entries, got %+v", entries)
	}
}

func TestUnbanDryRunIPv4(t *testing.T) {
	f := exec.NewFake()
	b := New(f)
	res, err := b.Unban(context.Background(), model.Entry{Value: "192.168.1.66"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("dry-run must not report a change")
	}
	want := "nft delete element ip sshguard attackers { 192.168.1.66 }"
	if len(res.Commands) != 1 || res.Commands[0] != want {
		t.Fatalf("commands = %v, want %q", res.Commands, want)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

func TestUnbanDryRunIPv6(t *testing.T) {
	b := New(exec.NewFake())
	res, err := b.Unban(context.Background(), model.Entry{Value: "2001:db8::1"}, true)
	if err != nil {
		t.Fatal(err)
	}
	want := "nft delete element ip6 sshguard attackers { 2001:db8::1 }"
	if len(res.Commands) != 1 || res.Commands[0] != want {
		t.Fatalf("commands = %v, want %q", res.Commands, want)
	}
}

func TestUnbanExecutes(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "nft", "delete", "element", "ip", "sshguard", "attackers", "{", "192.168.1.66", "}")
	b := New(f)
	res, err := b.Unban(context.Background(), model.Entry{Value: "192.168.1.66"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("executed unban should report a change")
	}
	if len(f.Calls) != 1 {
		t.Fatalf("expected one runner call, got %v", f.Calls)
	}
}

func hasValue(entries []model.Entry, value string) bool {
	for _, e := range entries {
		if e.Value == value {
			return true
		}
	}
	return false
}
