// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package haproxy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// socatKey is the FakeRunner invocation key shared by every runtime-socket call
// (all map commands go through the same socat argv; the command itself rides on
// stdin and is asserted via f.Inputs).
const socatKey = "socat - UNIX-CONNECT:/run/haproxy/admin.sock"

func TestListBansFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "show_map.txt"))
	if err != nil {
		t.Fatal(err)
	}
	f := exec.NewFake()
	f.Set(string(data), 0, "socat", "-", "UNIX-CONNECT:/run/haproxy/admin.sock")

	entries, err := New(f).ListBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
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
	if e.Origin != model.OriginHAProxy || e.Backend != string(model.OriginHAProxy) {
		t.Fatalf("entry[0] attribution = %+v", e)
	}
	if e.NativeID != "0x55c8f1a2b000" {
		t.Fatalf("entry[0] native id = %q", e.NativeID)
	}
	if entries[2].Family != model.FamilyIPv6 || entries[2].Value != "2001:db8::1" {
		t.Fatalf("entry[2] = %+v", entries[2])
	}

	// ListBans read the deny map over the socket with the right command on stdin.
	if got := f.Inputs[socatKey]; got != "show map /etc/haproxy/omniban_deny.map\n" {
		t.Fatalf("stdin = %q", got)
	}
}

func TestListBansNoSocat(t *testing.T) {
	f := exec.NewFake()
	f.Missing = []string{"socat"}
	entries, err := New(f).ListBans(context.Background())
	if err != nil {
		t.Fatalf("missing socat should be empty, not error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("want 0 entries, got %d", len(entries))
	}
	if len(f.Calls) != 0 {
		t.Fatalf("must not invoke the runner without socat: %v", f.Calls)
	}
}

func TestListBansSocketError(t *testing.T) {
	f := exec.NewFake()
	f.Set("Can't connect to socket", 1, "socat", "-", "UNIX-CONNECT:/run/haproxy/admin.sock")
	entries, err := New(f).ListBans(context.Background())
	if err != nil {
		t.Fatalf("socket error should be tolerated as empty: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("want 0 entries on socket error, got %d", len(entries))
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
	wantCmds := []string{
		"socat - UNIX-CONNECT:/run/haproxy/admin.sock",
		"set map /etc/haproxy/omniban_deny.map 5.6.7.8 ok",
	}
	if len(res.Commands) != 2 || res.Commands[0] != wantCmds[0] || res.Commands[1] != wantCmds[1] {
		t.Fatalf("commands = %v, want %v", res.Commands, wantCmds)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
	if len(f.Inputs) != 0 {
		t.Fatalf("dry-run must not write to the socket: %v", f.Inputs)
	}
}

func TestUnbanDryRun(t *testing.T) {
	f := exec.NewFake()
	res, err := New(f).Unban(context.Background(), model.Entry{Value: "1.2.3.4"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed || !res.DryRun {
		t.Fatalf("dry-run flags = %+v", res)
	}
	want := "del map /etc/haproxy/omniban_deny.map 1.2.3.4"
	if len(res.Commands) != 2 || res.Commands[1] != want {
		t.Fatalf("commands = %v, want del cmd %q", res.Commands, want)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

func TestBanExecutes(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "socat", "-", "UNIX-CONNECT:/run/haproxy/admin.sock")
	res, err := New(f).Ban(context.Background(), model.ActionRequest{Value: "9.9.9.9", Scope: model.ScopeIP})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.DryRun {
		t.Fatalf("executed ban flags = %+v", res)
	}
	if len(f.Calls) != 1 || f.Calls[0] != socatKey {
		t.Fatalf("runner calls = %v", f.Calls)
	}
	got := f.Inputs[socatKey]
	if want := "set map /etc/haproxy/omniban_deny.map 9.9.9.9 ok\n"; got != want {
		t.Fatalf("stdin = %q, want %q", got, want)
	}
	if !strings.HasSuffix(strings.TrimSpace(got), "ok") {
		t.Fatalf("set map command malformed: %q", got)
	}
}

func TestUnbanExecutes(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "socat", "-", "UNIX-CONNECT:/run/haproxy/admin.sock")
	res, err := New(f).Unban(context.Background(), model.Entry{Value: "2001:db8::1"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("executed unban should report a change")
	}
	if len(f.Calls) != 1 || f.Calls[0] != socatKey {
		t.Fatalf("runner calls = %v", f.Calls)
	}
	if got := f.Inputs[socatKey]; got != "del map /etc/haproxy/omniban_deny.map 2001:db8::1\n" {
		t.Fatalf("stdin = %q", got)
	}
}

func TestMutationNoSocat(t *testing.T) {
	f := exec.NewFake()
	f.Missing = []string{"socat"}
	if _, err := New(f).Ban(context.Background(), model.ActionRequest{Value: "5.6.7.8"}); err == nil {
		t.Fatal("ban without socat must error")
	}
	if _, err := New(f).Unban(context.Background(), model.Entry{Value: "5.6.7.8"}, false); err == nil {
		t.Fatal("unban without socat must error")
	}
	if len(f.Calls) != 0 {
		t.Fatalf("must not invoke the runner without socat: %v", f.Calls)
	}
}
