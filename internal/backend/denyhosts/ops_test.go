// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package denyhosts

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// newTestBackend wires a Backend onto a fresh temp dir, copying the fixtures in
// so mutations operate on disposable files. It returns the backend, the runner,
// and the temp dir.
func newTestBackend(t *testing.T) (*Backend, *exec.FakeRunner, string) {
	t.Helper()
	dir := t.TempDir()
	hostsDeny := filepath.Join(dir, "hosts.deny")
	allowed := filepath.Join(dir, "allowed-hosts")
	copyFixture(t, "hosts.deny", hostsDeny)
	copyFixture(t, "allowed-hosts", allowed)
	// Seed the work files so unban has something to strip.
	mustWrite(t, filepath.Join(dir, "hosts"), "1.2.3.4\n5.6.7.8\n")
	mustWrite(t, filepath.Join(dir, "hosts-restricted"), "1.2.3.4\n5.6.7.8\n")

	f := exec.NewFake()
	b := New(f)
	b.hostsDeny = hostsDeny
	b.workDir = dir
	b.allowedHosts = allowed
	return b, f, dir
}

func copyFixture(t *testing.T, name, dst string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, dst, string(data))
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestListBans(t *testing.T) {
	b, _, _ := newTestBackend(t)
	entries, err := b.ListBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 bans (comment skipped), got %d: %+v", len(entries), entries)
	}
	e := entries[0]
	if e.Value != "1.2.3.4" || e.Family != model.FamilyIPv4 || e.Scope != model.ScopeIP {
		t.Fatalf("entry[0] = %+v", e)
	}
	if e.Kind != model.KindBan || e.Origin != model.OriginDenyHosts || e.Backend != "denyhosts" {
		t.Fatalf("entry[0] attribution = %+v", e)
	}
	if e.Direction != model.DirInbound {
		t.Fatalf("entry[0] direction = %v", e.Direction)
	}
	if entries[1].Value != "5.6.7.8" {
		t.Fatalf("entry[1] = %+v", entries[1])
	}
}

func TestListAllows(t *testing.T) {
	b, _, _ := newTestBackend(t)
	entries, err := b.ListAllows(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 allows, got %d: %+v", len(entries), entries)
	}
	if entries[0].Value != "10.0.0.1" || entries[0].Kind != model.KindAllow {
		t.Fatalf("allow[0] = %+v", entries[0])
	}
	if entries[1].Value != "192.168.0.0/16" || entries[1].Scope != model.ScopeRange {
		t.Fatalf("allow[1] = %+v", entries[1])
	}
}

func TestListBansMissingFile(t *testing.T) {
	f := exec.NewFake()
	b := New(f)
	b.hostsDeny = filepath.Join(t.TempDir(), "absent")
	entries, err := b.ListBans(context.Background())
	if err != nil {
		t.Fatalf("missing hosts.deny should not error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("want 0 entries, got %d", len(entries))
	}
}

func TestBanExecutes(t *testing.T) {
	b, f, dir := newTestBackend(t)
	f.Set("", 0, "systemctl", "stop", "denyhosts")
	f.Set("", 0, "systemctl", "start", "denyhosts")

	res, err := b.Ban(context.Background(), model.ActionRequest{Value: "9.9.9.9", Scope: model.ScopeIP})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.DryRun {
		t.Fatalf("executed ban: Changed=%v DryRun=%v", res.Changed, res.DryRun)
	}

	// The deny line was appended.
	deny := readFile(t, b.hostsDeny)
	if !strings.Contains(deny, "sshd: 9.9.9.9") {
		t.Fatalf("hosts.deny missing ban line:\n%s", deny)
	}
	// Both work files updated.
	if !strings.Contains(readFile(t, filepath.Join(dir, "hosts")), "9.9.9.9") {
		t.Fatal("work file hosts missing the ip")
	}
	if !strings.Contains(readFile(t, filepath.Join(dir, "hosts-restricted")), "9.9.9.9") {
		t.Fatal("work file hosts-restricted missing the ip")
	}
	// A backup was created before editing hosts.deny.
	if _, err := os.Stat(b.hostsDeny + ".omniban.bak"); err != nil {
		t.Fatalf("expected hosts.deny backup: %v", err)
	}
	// systemctl stop+start ran.
	joined := strings.Join(f.Calls, "|")
	if !strings.Contains(joined, "systemctl stop denyhosts") || !strings.Contains(joined, "systemctl start denyhosts") {
		t.Fatalf("systemctl stop/start not invoked: %v", f.Calls)
	}
}

func TestBanIdempotent(t *testing.T) {
	b, f, _ := newTestBackend(t)
	f.Set("", 0, "systemctl", "stop", "denyhosts")
	f.Set("", 0, "systemctl", "start", "denyhosts")

	// 1.2.3.4 is already in the fixture; banning again must not duplicate it.
	if _, err := b.Ban(context.Background(), model.ActionRequest{Value: "1.2.3.4", Scope: model.ScopeIP}); err != nil {
		t.Fatal(err)
	}
	deny := readFile(t, b.hostsDeny)
	if n := strings.Count(deny, "1.2.3.4"); n != 1 {
		t.Fatalf("want exactly 1 occurrence of 1.2.3.4, got %d:\n%s", n, deny)
	}
}

func TestBanDryRun(t *testing.T) {
	b, f, dir := newTestBackend(t)
	before := readFile(t, b.hostsDeny)

	res, err := b.Ban(context.Background(), model.ActionRequest{Value: "9.9.9.9", Scope: model.ScopeIP, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("dry-run must not report a change")
	}
	if !res.DryRun || res.Message != "dry-run: not executed" {
		t.Fatalf("dry-run flags = %+v", res)
	}
	if len(res.Commands) != 5 {
		t.Fatalf("want 5 recorded steps, got %d: %v", len(res.Commands), res.Commands)
	}
	// No runner calls.
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
	// Files unchanged, no backup created.
	if got := readFile(t, b.hostsDeny); got != before {
		t.Fatalf("dry-run modified hosts.deny:\n%s", got)
	}
	if _, err := os.Stat(b.hostsDeny + ".omniban.bak"); !os.IsNotExist(err) {
		t.Fatalf("dry-run must not create a backup (err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "hosts") + ".omniban.bak"); !os.IsNotExist(err) {
		t.Fatal("dry-run must not back up work files")
	}
}

func TestBanIPv6Rejected(t *testing.T) {
	b, f, _ := newTestBackend(t)
	_, err := b.Ban(context.Background(), model.ActionRequest{Value: "2001:db8::1", Scope: model.ScopeIP})
	if err == nil {
		t.Fatal("IPv6 ban should error")
	}
	if !strings.Contains(err.Error(), "IPv6") {
		t.Fatalf("error should mention IPv6: %v", err)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("rejected ban must not invoke the runner: %v", f.Calls)
	}
}

func TestUnbanExecutes(t *testing.T) {
	b, f, dir := newTestBackend(t)
	f.Set("", 0, "systemctl", "stop", "denyhosts")
	f.Set("", 0, "systemctl", "start", "denyhosts")

	res, err := b.Unban(context.Background(), model.Entry{Value: "1.2.3.4"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("executed unban should report a change")
	}
	deny := readFile(t, b.hostsDeny)
	if strings.Contains(deny, "1.2.3.4") {
		t.Fatalf("hosts.deny still contains the ip:\n%s", deny)
	}
	if !strings.Contains(deny, "5.6.7.8") {
		t.Fatalf("unban dropped the wrong line:\n%s", deny)
	}
	if strings.Contains(readFile(t, filepath.Join(dir, "hosts")), "1.2.3.4") {
		t.Fatal("work file hosts still contains the ip")
	}
	if strings.Contains(readFile(t, filepath.Join(dir, "hosts-restricted")), "1.2.3.4") {
		t.Fatal("work file hosts-restricted still contains the ip")
	}
	if _, err := os.Stat(b.hostsDeny + ".omniban.bak"); err != nil {
		t.Fatalf("expected backup before unban edit: %v", err)
	}
}

func TestUnbanTokenBoundary(t *testing.T) {
	b, f, _ := newTestBackend(t)
	f.Set("", 0, "systemctl", "stop", "denyhosts")
	f.Set("", 0, "systemctl", "start", "denyhosts")
	mustWrite(t, b.hostsDeny, "sshd: 1.2.3.4\nsshd: 1.2.3.40\n")

	if _, err := b.Unban(context.Background(), model.Entry{Value: "1.2.3.4"}, false); err != nil {
		t.Fatal(err)
	}
	deny := readFile(t, b.hostsDeny)
	if strings.Contains(deny, "sshd: 1.2.3.4\n") && !strings.Contains(deny, "1.2.3.40") {
		t.Fatalf("token boundary mismatch dropped 1.2.3.40:\n%s", deny)
	}
	if !strings.Contains(deny, "1.2.3.40") {
		t.Fatalf("unban removed the wrong (prefix-matching) ip:\n%s", deny)
	}
	if strings.Contains(deny, "sshd: 1.2.3.4\n") {
		t.Fatalf("unban failed to remove the exact ip:\n%s", deny)
	}
}

func TestUnbanDryRun(t *testing.T) {
	b, f, _ := newTestBackend(t)
	before := readFile(t, b.hostsDeny)

	res, err := b.Unban(context.Background(), model.Entry{Value: "1.2.3.4"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("dry-run unban must not change anything")
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
	if got := readFile(t, b.hostsDeny); got != before {
		t.Fatalf("dry-run modified hosts.deny:\n%s", got)
	}
}

func TestAllowExecutes(t *testing.T) {
	b, _, _ := newTestBackend(t)
	res, err := b.Allow(context.Background(), model.ActionRequest{Value: "172.16.0.1", Scope: model.ScopeIP})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("executed allow should report a change")
	}
	if !strings.Contains(readFile(t, b.allowedHosts), "172.16.0.1") {
		t.Fatal("allowed-hosts missing the new entry")
	}
	if _, err := os.Stat(b.allowedHosts + ".omniban.bak"); err != nil {
		t.Fatalf("expected allowed-hosts backup: %v", err)
	}
}

func TestRemoveAllowExecutes(t *testing.T) {
	b, _, _ := newTestBackend(t)
	res, err := b.RemoveAllow(context.Background(), model.Entry{Value: "10.0.0.1"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("executed remove-allow should report a change")
	}
	if strings.Contains(readFile(t, b.allowedHosts), "10.0.0.1") {
		t.Fatal("allowed-hosts still contains the removed entry")
	}
}
