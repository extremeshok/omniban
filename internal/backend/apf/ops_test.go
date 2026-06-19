// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package apf

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// newFromFixtures returns an APF backend whose rule files point at the golden
// fixtures under testdata/.
func newFromFixtures(r exec.Runner) *Backend {
	b := New(r)
	b.denyFile = filepath.Join("testdata", "deny_hosts.rules")
	b.allowFile = filepath.Join("testdata", "allow_hosts.rules")
	return b
}

func TestListBansParsesFixture(t *testing.T) {
	b := newFromFixtures(exec.NewFake())
	entries, err := b.ListBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Fatalf("want 5 deny entries, got %d: %+v", len(entries), entries)
	}

	cases := []struct {
		idx    int
		value  string
		family model.Family
		scope  model.Scope
		detail string
	}{
		{0, "1.2.3.4", model.FamilyIPv4, model.ScopeIP, "{bfd.sshd} lfd: (sshd) Failed SSH login from 1.2.3.4"},
		{1, "198.51.100.7", model.FamilyIPv4, model.ScopeIP, "omniban: manual"},
		{2, "203.0.113.0/24", model.FamilyIPv4, model.ScopeRange, "blocked subnet"},
		{3, "5.6.7.0/24", model.FamilyIPv4, model.ScopeRange, "manual advanced rule"},
		{4, "2001:db8::1", model.FamilyIPv6, model.ScopeIP, "{bfd.exim} brute force from v6"},
	}
	for _, c := range cases {
		e := entries[c.idx]
		if e.Value != c.value || e.Family != c.family || e.Scope != c.scope {
			t.Errorf("entry[%d] = {value:%q family:%q scope:%q}, want {%q %q %q}",
				c.idx, e.Value, e.Family, e.Scope, c.value, c.family, c.scope)
		}
		if e.Detail != c.detail {
			t.Errorf("entry[%d] detail = %q, want %q", c.idx, e.Detail, c.detail)
		}
		if e.Kind != model.KindBan || e.Origin != model.OriginAPF ||
			e.Backend != string(model.OriginAPF) || e.Direction != model.DirInbound {
			t.Errorf("entry[%d] attribution = %+v", c.idx, e)
		}
	}
}

// TestAdvancedSyntaxYieldsCIDR pins the headline parsing requirement: the
// "d=22:s=5.6.7.0/24" advanced line must resolve to the embedded CIDR.
func TestAdvancedSyntaxYieldsCIDR(t *testing.T) {
	b := newFromFixtures(exec.NewFake())
	entries, err := b.ListBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var found *model.Entry
	for i := range entries {
		if entries[i].Value == "5.6.7.0/24" {
			found = &entries[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("advanced-syntax line did not yield 5.6.7.0/24: %+v", entries)
	}
	if found.Scope != model.ScopeRange || found.Family != model.FamilyIPv4 {
		t.Fatalf("advanced entry = %+v", found)
	}
}

func TestListAllowsParsesFixture(t *testing.T) {
	b := newFromFixtures(exec.NewFake())
	entries, err := b.ListAllows(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("want 3 allow entries, got %d: %+v", len(entries), entries)
	}
	if entries[0].Value != "10.0.0.5" || entries[0].Kind != model.KindAllow {
		t.Fatalf("allow[0] = %+v", entries[0])
	}
	if entries[1].Value != "192.168.0.0/16" || entries[1].Scope != model.ScopeRange {
		t.Fatalf("allow[1] = %+v", entries[1])
	}
	// advanced allow line yields the embedded host
	if entries[2].Value != "8.8.8.8" || entries[2].Scope != model.ScopeIP {
		t.Fatalf("allow[2] = %+v", entries[2])
	}
}

func TestListBansMissingFileIsEmpty(t *testing.T) {
	b := New(exec.NewFake())
	b.denyFile = filepath.Join(t.TempDir(), "does_not_exist.rules")
	entries, err := b.ListBans(context.Background())
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("want empty, got %+v", entries)
	}
}

func TestBanDryRun(t *testing.T) {
	f := exec.NewFake()
	res, err := New(f).Ban(context.Background(), model.ActionRequest{
		Value: "5.6.7.8", Scope: model.ScopeIP, Reason: "ssh brute", DryRun: true,
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
	want := "apf -d 5.6.7.8 omniban: ssh brute"
	if len(res.Commands) != 1 || res.Commands[0] != want {
		t.Fatalf("commands = %v, want %q", res.Commands, want)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

func TestUnbanDryRun(t *testing.T) {
	f := exec.NewFake()
	res, err := New(f).Unban(context.Background(), model.Entry{Value: "5.6.7.8"}, true)
	if err != nil {
		t.Fatal(err)
	}
	// File removal is authoritative; "apf -u" is a best-effort live-rule drop.
	if len(res.Commands) != 2 ||
		!strings.HasPrefix(res.Commands[0], `remove lines matching "5.6.7.8"`) ||
		res.Commands[1] != "apf -u 5.6.7.8" {
		t.Fatalf("commands = %v", res.Commands)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

// TestUnbanRemovesFromFile is the regression for the bug a live APF run found:
// "apf -u" does not clean deny_hosts.rules, so omniban must remove the lines
// itself — both the bare rule line and APF's "# added ..." comment line.
func TestUnbanRemovesFromFile(t *testing.T) {
	dir := t.TempDir()
	deny := filepath.Join(dir, "deny_hosts.rules")
	body := "# added 203.0.113.20 on 06/19/26 with comment: omniban: manual\n" +
		"203.0.113.20\n" +
		"198.51.100.7\n"
	if err := os.WriteFile(deny, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	b := New(exec.NewFake())
	b.denyFile = deny

	res, err := b.Unban(context.Background(), model.Entry{Value: "203.0.113.20"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("unban should report a change")
	}
	data, _ := os.ReadFile(deny)
	if strings.Contains(string(data), "203.0.113.20") {
		t.Fatalf("entry (and its comment line) not removed:\n%s", data)
	}
	if !strings.Contains(string(data), "198.51.100.7") {
		t.Fatalf("unrelated entry must remain:\n%s", data)
	}
	if _, err := os.Stat(deny + ".omniban.bak"); err != nil {
		t.Fatalf("backup not created: %v", err)
	}
}

func TestAllowExecutes(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "apf", "-a", "9.9.9.9", "omniban: trusted")
	res, err := New(f).Allow(context.Background(), model.ActionRequest{
		Value: "9.9.9.9", Scope: model.ScopeIP, Reason: "trusted",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("executed allow should report a change")
	}
	if res.DryRun {
		t.Fatal("executed allow must not be marked dry-run")
	}
	wantCall := "apf -a 9.9.9.9 omniban: trusted"
	if len(f.Calls) != 1 || f.Calls[0] != wantCall {
		t.Fatalf("runner calls = %v, want %q", f.Calls, wantCall)
	}
}

func TestBanWithoutReasonTagsManual(t *testing.T) {
	f := exec.NewFake()
	res, err := New(f).Ban(context.Background(), model.ActionRequest{
		Value: "5.6.7.8", Scope: model.ScopeIP, DryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "apf -d 5.6.7.8 omniban: manual"
	if res.Commands[0] != want {
		t.Fatalf("commands[0] = %q, want %q", res.Commands[0], want)
	}
}

func TestMutationWithoutBinaryErrors(t *testing.T) {
	f := exec.NewFake()
	f.Missing = []string{"apf"} // not on PATH; canonical path also absent in tests
	_, err := New(f).Ban(context.Background(), model.ActionRequest{Value: "5.6.7.8"})
	if err == nil {
		t.Fatal("ban without an apf binary should error")
	}
}
