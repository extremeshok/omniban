// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package fail2ban

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestParseJailList(t *testing.T) {
	jails := parseJailList(fixture(t, "status.txt"))
	want := []string{"sshd", "nginx-http-auth"}
	if len(jails) != len(want) {
		t.Fatalf("parseJailList = %v, want %v", jails, want)
	}
	for i := range want {
		if jails[i] != want[i] {
			t.Fatalf("jail[%d] = %q, want %q", i, jails[i], want[i])
		}
	}
}

func TestParseBannedIPs(t *testing.T) {
	ips := parseBannedIPs(fixture(t, "status_sshd.txt"))
	want := []string{"1.2.3.4", "5.6.7.8", "2001:db8::1"}
	if len(ips) != len(want) {
		t.Fatalf("parseBannedIPs = %v, want %v", ips, want)
	}
	for i := range want {
		if ips[i] != want[i] {
			t.Fatalf("ip[%d] = %q, want %q", i, ips[i], want[i])
		}
	}
}

func TestParseBannedIPsEmpty(t *testing.T) {
	out := "Status for the jail: empty\n`- Actions\n   `- Banned IP list:\t\n"
	if ips := parseBannedIPs(out); len(ips) != 0 {
		t.Fatalf("empty banned list should yield no IPs, got %v", ips)
	}
}

func TestListBansViaRunner(t *testing.T) {
	f := exec.NewFake()
	f.Set(fixture(t, "status.txt"), 0, "fail2ban-client", "status")
	f.Set(fixture(t, "status_sshd.txt"), 0, "fail2ban-client", "status", "sshd")
	// nginx-http-auth jail has no bans.
	f.Set("`- Banned IP list:\t\n", 0, "fail2ban-client", "status", "nginx-http-auth")

	entries, err := New(f).ListBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("ListBans = %d entries, want 3", len(entries))
	}

	e := entries[0]
	if e.Value != "1.2.3.4" || e.Family != model.FamilyIPv4 || e.Scope != model.ScopeIP {
		t.Fatalf("entry[0] = %+v", e)
	}
	if e.Detail != "sshd" || e.Origin != model.OriginFail2ban || e.Backend != "fail2ban" {
		t.Fatalf("entry[0] attribution = %+v", e)
	}
	if e.Kind != model.KindBan || e.Direction != model.DirInbound {
		t.Fatalf("entry[0] kind/direction = %+v", e)
	}
	if entries[2].Value != "2001:db8::1" || entries[2].Family != model.FamilyIPv6 {
		t.Fatalf("entry[2] = %+v", entries[2])
	}
}

func TestUnbanDryRunWithJail(t *testing.T) {
	f := exec.NewFake()
	res, err := New(f).Unban(context.Background(), model.Entry{Value: "1.2.3.4", Detail: "sshd"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("dry-run must not report a change")
	}
	want := "fail2ban-client set sshd unbanip 1.2.3.4"
	if len(res.Commands) != 1 || res.Commands[0] != want {
		t.Fatalf("commands = %v, want %q", res.Commands, want)
	}
	if res.DryRun != true || res.Message != "dry-run: not executed" {
		t.Fatalf("dry-run flags = %+v", res)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

func TestUnbanDryRunNoJail(t *testing.T) {
	f := exec.NewFake()
	res, err := New(f).Unban(context.Background(), model.Entry{Value: "5.6.7.8"}, true)
	if err != nil {
		t.Fatal(err)
	}
	want := "fail2ban-client unban 5.6.7.8"
	if len(res.Commands) != 1 || res.Commands[0] != want {
		t.Fatalf("commands = %v, want %q", res.Commands, want)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

func TestUnbanExecutes(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "fail2ban-client", "set", "sshd", "unbanip", "1.2.3.4")
	res, err := New(f).Unban(context.Background(), model.Entry{Value: "1.2.3.4", Detail: "sshd"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("executed unban should report a change")
	}
	if len(f.Calls) != 1 {
		t.Fatalf("executed unban should invoke the runner once: %v", f.Calls)
	}
}
