// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package modsecurity

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// newBackend returns a Backend whose blocklist points at body in a temp dir and
// a FakeRunner for the nginx reload, so tests touch no real files or binaries.
func newBackend(t *testing.T, body string) (*Backend, *exec.FakeRunner) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "omniban-blocklist.txt")
	if body != "" {
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f := exec.NewFake()
	f.Set("", 0, "nginx", "-s", "reload")
	b := New(f)
	b.blocklist = p
	return b, f
}

func TestListBansParse(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("testdata", "blocklist.txt"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := newBackend(t, string(body))

	entries, err := b.ListBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Fatalf("want 5 entries, got %d: %+v", len(entries), entries)
	}
	byValue := map[string]model.Entry{}
	for _, e := range entries {
		if e.Backend != string(model.OriginModSecurity) || e.Origin != model.OriginModSecurity {
			t.Fatalf("bad attribution: %+v", e)
		}
		if e.Kind != model.KindBan || e.Direction != model.DirInbound {
			t.Fatalf("bad kind/direction: %+v", e)
		}
		byValue[e.Value] = e
	}

	cases := []struct {
		value  string
		scope  model.Scope
		family model.Family
	}{
		{"203.0.113.7", model.ScopeIP, model.FamilyIPv4},
		{"198.51.100.0/24", model.ScopeRange, model.FamilyIPv4},
		{"2001:db8:dead:beef::1", model.ScopeIP, model.FamilyIPv6},
		{"2001:db8:abcd::/48", model.ScopeRange, model.FamilyIPv6},
		{"192.0.2.44", model.ScopeIP, model.FamilyIPv4}, // trailing comment stripped
	}
	for _, c := range cases {
		e, ok := byValue[c.value]
		if !ok {
			t.Fatalf("missing entry %q", c.value)
		}
		if e.Scope != c.scope {
			t.Errorf("%s: scope = %q, want %q", c.value, e.Scope, c.scope)
		}
		if e.Family != c.family {
			t.Errorf("%s: family = %q, want %q", c.value, e.Family, c.family)
		}
	}
}

func TestBanAppendsAndReloads(t *testing.T) {
	b, f := newBackend(t, "203.0.113.7\n")

	res, err := b.Ban(context.Background(), model.ActionRequest{Value: "198.51.100.5", Scope: model.ScopeIP})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.DryRun {
		t.Fatalf("ban should change and not be dry-run: %+v", res)
	}

	// File now contains both the old and the new value.
	data, _ := os.ReadFile(b.blocklist)
	got := string(data)
	if !strings.Contains(got, "203.0.113.7") || !strings.Contains(got, "198.51.100.5") {
		t.Fatalf("blocklist missing entries:\n%s", got)
	}

	// Backup created with the pre-edit content.
	bak, err := os.ReadFile(b.blocklist + ".omniban.bak")
	if err != nil {
		t.Fatalf("backup not created: %v", err)
	}
	if strings.Contains(string(bak), "198.51.100.5") {
		t.Fatalf("backup should hold pre-edit content:\n%s", bak)
	}

	// nginx reload was invoked exactly once.
	want := exec.Key("nginx", []string{"-s", "reload"})
	if len(f.Calls) != 1 || f.Calls[0] != want {
		t.Fatalf("calls = %v, want exactly [%q]", f.Calls, want)
	}

	// Commands record both the file edit and the reload.
	if len(res.Commands) != 2 || !strings.Contains(res.Commands[0], b.blocklist) || res.Commands[1] != "nginx -s reload" {
		t.Fatalf("unexpected commands: %#v", res.Commands)
	}
}

func TestBanIdempotent(t *testing.T) {
	b, f := newBackend(t, "203.0.113.7\n")
	res, err := b.Ban(context.Background(), model.ActionRequest{Value: "203.0.113.7", Scope: model.ScopeIP})
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("banning an already-present value must be a no-op")
	}
	if len(f.Calls) != 0 {
		t.Fatalf("no reload expected on no-op ban, got %v", f.Calls)
	}
}

func TestBanDryRun(t *testing.T) {
	b, f := newBackend(t, "203.0.113.7\n")
	before, _ := os.ReadFile(b.blocklist)

	res, err := b.Ban(context.Background(), model.ActionRequest{Value: "198.51.100.5", Scope: model.ScopeIP, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("dry-run must not change")
	}
	if !res.DryRun || res.Message != "dry-run: not executed" {
		t.Fatalf("dry-run metadata missing: %+v", res)
	}
	if len(res.Commands) != 2 {
		t.Fatalf("dry-run should still record both commands: %#v", res.Commands)
	}

	after, _ := os.ReadFile(b.blocklist)
	if string(before) != string(after) {
		t.Fatal("dry-run must not write the file")
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not call the runner, got %v", f.Calls)
	}
	if _, err := os.Stat(b.blocklist + ".omniban.bak"); !os.IsNotExist(err) {
		t.Fatal("dry-run must not create a backup")
	}
}

func TestUnbanRemovesAndReloads(t *testing.T) {
	// Token boundary: removing 203.0.113.7 must not touch 203.0.113.70.
	b, f := newBackend(t, "203.0.113.7\n203.0.113.70\n198.51.100.0/24\n")

	res, err := b.Unban(context.Background(), model.Entry{Value: "203.0.113.7"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("unban should change the file")
	}

	data, _ := os.ReadFile(b.blocklist)
	got := string(data)
	if strings.Contains(got, "203.0.113.7\n") {
		t.Fatalf("203.0.113.7 not removed:\n%s", got)
	}
	if !strings.Contains(got, "203.0.113.70") {
		t.Fatalf("203.0.113.70 must remain (token boundary):\n%s", got)
	}
	if !strings.Contains(got, "198.51.100.0/24") {
		t.Fatalf("unrelated entry must remain:\n%s", got)
	}

	want := exec.Key("nginx", []string{"-s", "reload"})
	if len(f.Calls) != 1 || f.Calls[0] != want {
		t.Fatalf("calls = %v, want exactly [%q]", f.Calls, want)
	}
}

func TestUnbanDryRun(t *testing.T) {
	b, f := newBackend(t, "203.0.113.7\n")
	before, _ := os.ReadFile(b.blocklist)

	res, err := b.Unban(context.Background(), model.Entry{Value: "203.0.113.7"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("dry-run unban must not change")
	}
	after, _ := os.ReadFile(b.blocklist)
	if string(before) != string(after) {
		t.Fatal("dry-run unban must not write the file")
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run unban must not call the runner, got %v", f.Calls)
	}
}

func TestUnbanAbsentNoReload(t *testing.T) {
	b, f := newBackend(t, "203.0.113.7\n")
	res, err := b.Unban(context.Background(), model.Entry{Value: "10.0.0.1"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("unbanning an absent value must be a no-op")
	}
	if len(f.Calls) != 0 {
		t.Fatalf("no reload expected on no-op unban, got %v", f.Calls)
	}
}

func TestReload(t *testing.T) {
	b, f := newBackend(t, "")
	if err := b.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := exec.Key("nginx", []string{"-s", "reload"})
	if len(f.Calls) != 1 || f.Calls[0] != want {
		t.Fatalf("calls = %v, want exactly [%q]", f.Calls, want)
	}
}
