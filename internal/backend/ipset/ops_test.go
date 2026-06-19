// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package ipset

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/extremeshok/omniban/internal/config"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

func readFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(data)
}

func TestListBans(t *testing.T) {
	f := exec.NewFake()
	f.Set(readFixture(t, "save4.txt"), 0, "ipset", "save", config.IPSetDeny4)
	f.Set(readFixture(t, "save6.txt"), 0, "ipset", "save", config.IPSetDeny6)

	b := New(f)
	got, err := b.ListBans(context.Background())
	if err != nil {
		t.Fatalf("ListBans: %v", err)
	}

	want := []model.Entry{
		{Value: "1.2.3.4", Family: model.FamilyIPv4, Scope: model.ScopeIP, Kind: model.KindBan, Direction: model.DirInbound, Origin: model.OriginIPSet, Backend: "ipset", Raw: "add omniban-deny4 1.2.3.4"},
		{Value: "10.0.0.0/24", Family: model.FamilyIPv4, Scope: model.ScopeRange, Kind: model.KindBan, Direction: model.DirInbound, Origin: model.OriginIPSet, Backend: "ipset", Raw: "add omniban-deny4 10.0.0.0/24"},
		{Value: "2001:db8::1", Family: model.FamilyIPv6, Scope: model.ScopeIP, Kind: model.KindBan, Direction: model.DirInbound, Origin: model.OriginIPSet, Backend: "ipset", Raw: "add omniban-deny6 2001:db8::1"},
		{Value: "2001:db8:abcd::/48", Family: model.FamilyIPv6, Scope: model.ScopeRange, Kind: model.KindBan, Direction: model.DirInbound, Origin: model.OriginIPSet, Backend: "ipset", Raw: "add omniban-deny6 2001:db8:abcd::/48"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ListBans entries mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestListBansMissingSet(t *testing.T) {
	f := exec.NewFake()
	// save4 present, save6 missing (non-zero exit) -> tolerated as empty.
	f.Set(readFixture(t, "save4.txt"), 0, "ipset", "save", config.IPSetDeny4)
	f.Set("", 1, "ipset", "save", config.IPSetDeny6)

	b := New(f)
	got, err := b.ListBans(context.Background())
	if err != nil {
		t.Fatalf("ListBans: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 entries from save4 only, got %d: %+v", len(got), got)
	}
}

func TestBanDryRun(t *testing.T) {
	f := exec.NewFake()
	b := New(f)

	res, err := b.Ban(context.Background(), model.ActionRequest{Value: "5.6.7.8", Scope: model.ScopeIP, DryRun: true})
	if err != nil {
		t.Fatalf("Ban dry-run: %v", err)
	}
	if !res.DryRun || res.Changed {
		t.Fatalf("dry-run flags wrong: DryRun=%v Changed=%v", res.DryRun, res.Changed)
	}
	if res.Message != "dry-run: not executed" {
		t.Fatalf("dry-run message = %q", res.Message)
	}
	if !contains(res.Commands, "ipset add -exist omniban-deny4 5.6.7.8") {
		t.Fatalf("missing add command in %+v", res.Commands)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("runner must not be called on dry-run, got %v", f.Calls)
	}
}

func TestBanExecuted(t *testing.T) {
	f := exec.NewFake()
	// Set and rule already present: ipset list and iptables -C return success.
	f.Set("Name: omniban-deny4", 0, "ipset", "list", config.IPSetDeny4)
	f.Set("", 0, "iptables", "-C", "INPUT", "-m", "set", "--match-set", config.IPSetDeny4, "src", "-j", "DROP")
	f.Set("", 0, "ipset", "add", "-exist", config.IPSetDeny4, "5.6.7.8")

	b := New(f)
	res, err := b.Ban(context.Background(), model.ActionRequest{Value: "5.6.7.8", Scope: model.ScopeIP})
	if err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if !res.Changed || res.DryRun {
		t.Fatalf("executed flags wrong: Changed=%v DryRun=%v", res.Changed, res.DryRun)
	}

	want := []string{
		"ipset list omniban-deny4",
		"iptables -C INPUT -m set --match-set omniban-deny4 src -j DROP",
		"ipset add -exist omniban-deny4 5.6.7.8",
	}
	if !reflect.DeepEqual(f.Calls, want) {
		t.Fatalf("runner calls mismatch:\n got %v\nwant %v", f.Calls, want)
	}
}

func TestBanExecutedCreatesScaffold(t *testing.T) {
	f := exec.NewFake()
	// Set absent (list fails) and rule absent (-C fails): create + insert run.
	f.Set("", 1, "ipset", "list", config.IPSetDeny4)
	f.Set("", 0, "ipset", "create", config.IPSetDeny4, "hash:net", "family", "inet", "-exist")
	f.Set("", 1, "iptables", "-C", "INPUT", "-m", "set", "--match-set", config.IPSetDeny4, "src", "-j", "DROP")
	f.Set("", 0, "iptables", "-I", "INPUT", "-m", "set", "--match-set", config.IPSetDeny4, "src", "-j", "DROP")
	f.Set("", 0, "ipset", "add", "-exist", config.IPSetDeny4, "5.6.7.8")

	b := New(f)
	if _, err := b.Ban(context.Background(), model.ActionRequest{Value: "5.6.7.8", Scope: model.ScopeIP}); err != nil {
		t.Fatalf("Ban: %v", err)
	}

	want := []string{
		"ipset list omniban-deny4",
		"ipset create omniban-deny4 hash:net family inet -exist",
		"iptables -C INPUT -m set --match-set omniban-deny4 src -j DROP",
		"iptables -I INPUT -m set --match-set omniban-deny4 src -j DROP",
		"ipset add -exist omniban-deny4 5.6.7.8",
	}
	if !reflect.DeepEqual(f.Calls, want) {
		t.Fatalf("scaffold calls mismatch:\n got %v\nwant %v", f.Calls, want)
	}
}

func TestBanIPv6UsesDeny6(t *testing.T) {
	f := exec.NewFake()
	f.Set("Name: omniban-deny6", 0, "ipset", "list", config.IPSetDeny6)
	f.Set("", 0, "ip6tables", "-C", "INPUT", "-m", "set", "--match-set", config.IPSetDeny6, "src", "-j", "DROP")
	f.Set("", 0, "ipset", "add", "-exist", config.IPSetDeny6, "2001:db8::99")

	b := New(f)
	res, err := b.Ban(context.Background(), model.ActionRequest{Value: "2001:db8::99", Scope: model.ScopeIP})
	if err != nil {
		t.Fatalf("Ban v6: %v", err)
	}
	if !res.Changed {
		t.Fatalf("expected Changed for v6 ban")
	}
	if !contains(f.Calls, "ipset add -exist omniban-deny6 2001:db8::99") {
		t.Fatalf("expected deny6 add, got %v", f.Calls)
	}
}

func TestUnbanDryRun(t *testing.T) {
	f := exec.NewFake()
	b := New(f)

	e := model.Entry{Value: "1.2.3.4", Family: model.FamilyIPv4, Scope: model.ScopeIP}
	res, err := b.Unban(context.Background(), e, true)
	if err != nil {
		t.Fatalf("Unban dry-run: %v", err)
	}
	if !res.DryRun || res.Changed {
		t.Fatalf("dry-run flags wrong: DryRun=%v Changed=%v", res.DryRun, res.Changed)
	}
	want := []string{"ipset del -exist omniban-deny4 1.2.3.4"}
	if !reflect.DeepEqual(res.Commands, want) {
		t.Fatalf("unban dry-run commands = %v, want %v", res.Commands, want)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("runner must not be called on dry-run, got %v", f.Calls)
	}
}

func TestUnbanExecuted(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "ipset", "del", "-exist", config.IPSetDeny4, "1.2.3.4")

	b := New(f)
	e := model.Entry{Value: "1.2.3.4", Family: model.FamilyIPv4, Scope: model.ScopeIP}
	res, err := b.Unban(context.Background(), e, false)
	if err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if !res.Changed {
		t.Fatalf("expected Changed for executed unban")
	}
	want := []string{"ipset del -exist omniban-deny4 1.2.3.4"}
	if !reflect.DeepEqual(f.Calls, want) {
		t.Fatalf("unban calls = %v, want %v", f.Calls, want)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
