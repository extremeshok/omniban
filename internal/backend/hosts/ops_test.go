// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package hosts

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/extremeshok/omniban/internal/config"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

func writeHosts(t *testing.T, body string) *Backend {
	t.Helper()
	p := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	b := New(exec.NewFake())
	b.path = p
	return b
}

func TestListBansWholeFile(t *testing.T) {
	body := "127.0.0.1 localhost\n" +
		"::1 localhost ip6-localhost\n" +
		"0.0.0.0 ads.example.com\n" +
		"127.0.0.1 tracker.example.net\n" +
		config.HostsBeginMarker + "\n" +
		"0.0.0.0 evil.com\n" +
		"::1 evil.com\n" +
		config.HostsEndMarker + "\n"
	b := writeHosts(t, body)

	entries, err := b.ListBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string][]model.Entry{}
	for _, e := range entries {
		byName[e.Value] = append(byName[e.Value], e)
	}
	if _, ok := byName["localhost"]; ok {
		t.Fatal("loopback name must not be treated as a sinkhole")
	}
	if len(byName["ads.example.com"]) != 1 || !byName["ads.example.com"][0].External {
		t.Fatalf("ads.example.com should be one External entry: %+v", byName["ads.example.com"])
	}
	if len(byName["tracker.example.net"]) != 1 || !byName["tracker.example.net"][0].External {
		t.Fatalf("tracker (127.0.0.1, non-loopback) should be External: %+v", byName["tracker.example.net"])
	}
	if len(byName["evil.com"]) != 2 {
		t.Fatalf("evil.com should appear for both 0.0.0.0 and ::1: %+v", byName["evil.com"])
	}
	for _, e := range byName["evil.com"] {
		if e.External {
			t.Fatal("managed-block entry must not be External")
		}
		if e.Direction != model.DirOutbound || e.Scope != model.ScopeDomain {
			t.Fatalf("bad attribution: %+v", e)
		}
	}
}

func TestBanCreatesManagedBlock(t *testing.T) {
	b := writeHosts(t, "127.0.0.1 localhost\n")
	res, err := b.Ban(context.Background(), model.ActionRequest{Value: "bad.example.org", Scope: model.ScopeDomain})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("ban should change the file")
	}
	data, _ := os.ReadFile(b.path)
	got := string(data)
	if !strings.Contains(got, config.HostsBeginMarker) || !strings.Contains(got, "0.0.0.0 bad.example.org") || !strings.Contains(got, "::1 bad.example.org") {
		t.Fatalf("managed block not written correctly:\n%s", got)
	}
	if _, err := os.Stat(b.path + ".omniban.bak"); err != nil {
		t.Fatalf("backup not created: %v", err)
	}

	// Idempotent: a second ban makes no change.
	res2, _ := b.Ban(context.Background(), model.ActionRequest{Value: "bad.example.org", Scope: model.ScopeDomain})
	if res2.Changed {
		t.Fatal("second ban should be a no-op")
	}
}

func TestBanDryRun(t *testing.T) {
	b := writeHosts(t, "127.0.0.1 localhost\n")
	before, _ := os.ReadFile(b.path)
	res, err := b.Ban(context.Background(), model.ActionRequest{Value: "bad.example.org", Scope: model.ScopeDomain, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("dry-run must not change")
	}
	after, _ := os.ReadFile(b.path)
	if string(before) != string(after) {
		t.Fatal("dry-run must not write the file")
	}
}

func TestUnbanExternalAndManaged(t *testing.T) {
	body := "0.0.0.0 ads.example.com bad.example.com\n" +
		config.HostsBeginMarker + "\n" +
		"0.0.0.0 evil.com\n" +
		"::1 evil.com\n" +
		config.HostsEndMarker + "\n"
	b := writeHosts(t, body)

	// Remove a managed sinkhole: both 0.0.0.0 and ::1 lines for evil.com go.
	if _, err := b.Unban(context.Background(), model.Entry{Value: "evil.com"}, false); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(b.path)
	if strings.Contains(string(data), "evil.com") {
		t.Fatalf("evil.com not fully removed:\n%s", data)
	}

	// Remove one name from a shared external line; the other name stays.
	if _, err := b.Unban(context.Background(), model.Entry{Value: "ads.example.com"}, false); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(b.path)
	if strings.Contains(string(data), "ads.example.com") {
		t.Fatal("ads.example.com should be removed")
	}
	if !strings.Contains(string(data), "0.0.0.0 bad.example.com") {
		t.Fatalf("co-located name should remain:\n%s", data)
	}
}
