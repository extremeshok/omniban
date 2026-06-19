// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package bunkerweb

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "bans.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseBansFixture(t *testing.T) {
	now := time.Unix(1_750_000_000, 0)
	entries := parseBans(fixture(t), now)
	if len(entries) != 3 {
		t.Fatalf("want 3 entries, got %d: %+v", len(entries), entries)
	}

	// Global timed IPv4 ban.
	e := entries[0]
	if e.Value != "203.0.113.45" || e.Family != model.FamilyIPv4 || e.Scope != model.ScopeIP {
		t.Fatalf("entry[0] = %+v", e)
	}
	if e.Kind != model.KindBan || e.Direction != model.DirInbound {
		t.Fatalf("entry[0] kind/direction = %+v", e)
	}
	if e.Origin != model.OriginBunkerWeb || e.Backend != string(model.OriginBunkerWeb) {
		t.Fatalf("entry[0] attribution = %+v", e)
	}
	if e.Detail != "US" || e.Reason != "bad behavior" {
		t.Fatalf("entry[0] detail/reason = %q / %q", e.Detail, e.Reason)
	}
	if e.ExpiresAt == nil {
		t.Fatalf("entry[0] expiry missing")
	}
	if got := e.ExpiresAt.Sub(now); got != 26*time.Hour { // 1 day + 2 hours
		t.Fatalf("entry[0] remaining = %v, want 26h", got)
	}

	// Global permanent IPv6 ban: unknown country dropped, no expiry.
	e = entries[1]
	if e.Value != "2001:db8::dead:beef" || e.Family != model.FamilyIPv6 {
		t.Fatalf("entry[1] = %+v", e)
	}
	if e.Detail != "" {
		t.Fatalf("entry[1] should drop unknown country, got detail %q", e.Detail)
	}
	if e.ExpiresAt != nil {
		t.Fatalf("entry[1] permanent ban must have nil expiry, got %v", e.ExpiresAt)
	}
	if e.Reason != "manual" {
		t.Fatalf("entry[1] reason = %q", e.Reason)
	}

	// Service-specific IPv4 ban: country + service folded into Detail.
	e = entries[2]
	if e.Value != "198.51.100.7" || e.Detail != "DE service=www.example.com" {
		t.Fatalf("entry[2] = %+v", e)
	}
	if e.ExpiresAt == nil {
		t.Fatalf("entry[2] expiry missing")
	}
	if got := e.ExpiresAt.Sub(now); got != 30*time.Minute+15*time.Second {
		t.Fatalf("entry[2] remaining = %v, want 30m15s", got)
	}
}

func TestParseHumanDuration(t *testing.T) {
	cases := map[string]time.Duration{
		"1 day and 2 hours":            26 * time.Hour,
		"30 minutes and 15 seconds":    30*time.Minute + 15*time.Second,
		"2 days":                       48 * time.Hour,
		"1 hour 1 minute and 1 second": time.Hour + time.Minute + time.Second,
		"":                             0,
	}
	for in, want := range cases {
		if got := parseHumanDuration(in); got != want {
			t.Errorf("parseHumanDuration(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestListBansViaRunner(t *testing.T) {
	f := exec.NewFake()
	f.Set(string(fixture(t)), 0, "bwcli", "bans")
	entries, err := New(f).ListBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("ListBans = %d entries", len(entries))
	}
	if len(f.Calls) != 1 || f.Calls[0] != "bwcli bans" {
		t.Fatalf("calls = %v", f.Calls)
	}
}

func TestBanDryRun(t *testing.T) {
	f := exec.NewFake()
	res, err := New(f).Ban(context.Background(), model.ActionRequest{
		Value: "5.6.7.8", Scope: model.ScopeIP, Duration: 2 * time.Hour, Reason: "test", DryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("dry-run must not report a change")
	}
	if res.Message != "dry-run: not executed" {
		t.Fatalf("dry-run message = %q", res.Message)
	}
	want := "bwcli ban 5.6.7.8 -exp 7200 -reason test"
	if len(res.Commands) != 1 || res.Commands[0] != want {
		t.Fatalf("commands = %v, want %q", res.Commands, want)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

func TestBanPermanentExecutes(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "bwcli", "ban", "9.9.9.9", "-exp", "0")
	res, err := New(f).Ban(context.Background(), model.ActionRequest{Value: "9.9.9.9", Scope: model.ScopeIP})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("executed ban should report a change")
	}
	if len(f.Calls) != 1 || f.Calls[0] != "bwcli ban 9.9.9.9 -exp 0" {
		t.Fatalf("calls = %v", f.Calls)
	}
}

func TestUnbanDryRun(t *testing.T) {
	f := exec.NewFake()
	res, err := New(f).Unban(context.Background(), model.Entry{Value: "1.2.3.4"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("dry-run must not report a change")
	}
	if len(res.Commands) != 1 || res.Commands[0] != "bwcli unban 1.2.3.4" {
		t.Fatalf("commands = %v", res.Commands)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

func TestUnbanExecutes(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "bwcli", "unban", "1.2.3.4")
	res, err := New(f).Unban(context.Background(), model.Entry{Value: "1.2.3.4"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("executed unban should report a change")
	}
	if len(f.Calls) != 1 || f.Calls[0] != "bwcli unban 1.2.3.4" {
		t.Fatalf("calls = %v", f.Calls)
	}
}

func TestMutationsWithoutBinary(t *testing.T) {
	f := exec.NewFake()
	f.Missing = []string{"bwcli"}
	if _, err := New(f).Ban(context.Background(), model.ActionRequest{Value: "1.2.3.4"}); err == nil {
		t.Fatal("Ban without bwcli should error")
	}
	if _, err := New(f).ListBans(context.Background()); err == nil {
		t.Fatal("ListBans without bwcli should error")
	}
}
