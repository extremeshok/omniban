// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package firewalld

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// fixtureRunner returns a FakeRunner whose `firewall-cmd --list-rich-rules`
// response is the golden testdata fixture.
func fixtureRunner(t *testing.T) *exec.FakeRunner {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "rich_rules.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	f := exec.NewFake()
	f.Set(string(data), 0, "firewall-cmd", "--list-rich-rules")
	return f
}

func TestListBansFixture(t *testing.T) {
	b := New(fixtureRunner(t))
	entries, err := b.ListBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// 2 drop + 2 reject rules carry a source address; accept and the
	// addressless service rule are excluded.
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
	if e.Origin != model.OriginFirewalld || e.Backend != string(model.OriginFirewalld) {
		t.Fatalf("entry[0] attribution = %+v", e)
	}

	// reject rule with a CIDR -> range scope.
	if entries[1].Value != "10.0.0.0/24" || entries[1].Scope != model.ScopeRange {
		t.Fatalf("entry[1] = %+v", entries[1])
	}
	if entries[2].Family != model.FamilyIPv6 || entries[2].Value != "2001:db8::1" {
		t.Fatalf("entry[2] = %+v", entries[2])
	}
	if entries[3].Family != model.FamilyIPv6 || entries[3].Scope != model.ScopeRange || entries[3].Value != "2001:db8::/48" {
		t.Fatalf("entry[3] = %+v", entries[3])
	}
}

func TestListAllowsFixture(t *testing.T) {
	b := New(fixtureRunner(t))
	entries, err := b.ListAllows(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// 3 accept rules carry a source address; the port-qualified accept also
	// has a source address, so 4 total. The addressless service accept is
	// excluded.
	if len(entries) != 4 {
		t.Fatalf("want 4 allows, got %d: %+v", len(entries), entries)
	}
	for i, e := range entries {
		if e.Kind != model.KindAllow {
			t.Fatalf("entry[%d] kind = %v", i, e.Kind)
		}
		if e.Origin != model.OriginFirewalld || e.Backend != string(model.OriginFirewalld) {
			t.Fatalf("entry[%d] attribution = %+v", i, e)
		}
		if e.Direction != model.DirInbound {
			t.Fatalf("entry[%d] direction = %v", i, e.Direction)
		}
	}
	if entries[0].Value != "192.0.2.10" || entries[0].Scope != model.ScopeIP {
		t.Fatalf("entry[0] = %+v", entries[0])
	}
	if entries[1].Value != "203.0.113.0/24" || entries[1].Scope != model.ScopeRange {
		t.Fatalf("entry[1] = %+v", entries[1])
	}
	if entries[2].Family != model.FamilyIPv6 || entries[2].Value != "2001:db8:cafe::5" {
		t.Fatalf("entry[2] = %+v", entries[2])
	}
	if entries[3].Value != "198.51.100.50" {
		t.Fatalf("entry[3] = %+v", entries[3])
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
	wantAdd := `firewall-cmd --permanent --add-rich-rule=rule family="ipv4" source address="5.6.7.8" drop`
	wantReload := "firewall-cmd --reload"
	if len(res.Commands) != 2 || res.Commands[0] != wantAdd || res.Commands[1] != wantReload {
		t.Fatalf("commands = %#v", res.Commands)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

func TestBanIPv6DryRun(t *testing.T) {
	f := exec.NewFake()
	res, err := New(f).Ban(context.Background(), model.ActionRequest{
		Value: "2001:db8::99", Scope: model.ScopeIP, DryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantAdd := `firewall-cmd --permanent --add-rich-rule=rule family="ipv6" source address="2001:db8::99" drop`
	if res.Commands[0] != wantAdd {
		t.Fatalf("commands[0] = %q", res.Commands[0])
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
	wantAdd := `firewall-cmd --permanent --add-rich-rule=rule family="ipv4" source address="192.0.2.10" accept`
	if len(res.Commands) != 2 || res.Commands[0] != wantAdd || res.Commands[1] != "firewall-cmd --reload" {
		t.Fatalf("commands = %#v", res.Commands)
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
	wantRemove := `firewall-cmd --permanent --remove-rich-rule=rule family="ipv4" source address="192.0.2.10" accept`
	if len(res.Commands) != 2 || res.Commands[0] != wantRemove || res.Commands[1] != "firewall-cmd --reload" {
		t.Fatalf("commands = %#v", res.Commands)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

func TestUnbanExecutes(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "firewall-cmd", "--permanent", `--remove-rich-rule=rule family="ipv4" source address="1.2.3.4" drop`)
	f.Set("", 0, "firewall-cmd", "--reload")

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
	wantCalls := []string{
		`firewall-cmd --permanent --remove-rich-rule=rule family="ipv4" source address="1.2.3.4" drop`,
		"firewall-cmd --reload",
	}
	if len(f.Calls) != len(wantCalls) {
		t.Fatalf("runner calls = %#v", f.Calls)
	}
	for i, w := range wantCalls {
		if f.Calls[i] != w {
			t.Fatalf("call[%d] = %q, want %q", i, f.Calls[i], w)
		}
	}
}

func TestBanExecutes(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "firewall-cmd", "--permanent", `--add-rich-rule=rule family="ipv4" source address="9.9.9.9" drop`)
	f.Set("", 0, "firewall-cmd", "--reload")

	res, err := New(f).Ban(context.Background(), model.ActionRequest{Value: "9.9.9.9", Scope: model.ScopeIP})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("executed ban should report a change")
	}
	wantCalls := []string{
		`firewall-cmd --permanent --add-rich-rule=rule family="ipv4" source address="9.9.9.9" drop`,
		"firewall-cmd --reload",
	}
	if len(f.Calls) != len(wantCalls) {
		t.Fatalf("runner calls = %#v", f.Calls)
	}
	for i, w := range wantCalls {
		if f.Calls[i] != w {
			t.Fatalf("call[%d] = %q, want %q", i, f.Calls[i], w)
		}
	}
}

func TestReloadExecutes(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "firewall-cmd", "--reload")
	if err := New(f).Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.Calls) != 1 || f.Calls[0] != "firewall-cmd --reload" {
		t.Fatalf("reload calls = %v", f.Calls)
	}
}
