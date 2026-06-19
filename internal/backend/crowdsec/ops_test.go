// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package crowdsec

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
	data, err := os.ReadFile(filepath.Join("testdata", "decisions_list.json"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseDecisionsFixture(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	entries, err := parseDecisions(fixture(t), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("want 3 entries (captcha skipped), got %d", len(entries))
	}

	e := entries[0]
	if e.Value != "1.2.3.4" || e.Family != model.FamilyIPv4 || e.Scope != model.ScopeIP {
		t.Fatalf("entry[0] = %+v", e)
	}
	if e.NativeID != "4" || e.Origin != model.OriginCrowdSec || e.Detail != "crowdsecurity/ssh-bf" {
		t.Fatalf("entry[0] attribution = %+v", e)
	}
	if e.ExpiresAt == nil || !e.ExpiresAt.After(now) {
		t.Fatalf("entry[0] expiry not set in the future: %+v", e.ExpiresAt)
	}
	if entries[1].Scope != model.ScopeRange || entries[1].Value != "10.0.0.0/24" {
		t.Fatalf("entry[1] = %+v", entries[1])
	}
	if entries[2].Family != model.FamilyIPv6 {
		t.Fatalf("entry[2] family = %v", entries[2].Family)
	}
}

// TestParseDecisionsFlatSchema pins backward-compatibility with older cscli
// versions that emit a flat array of decisions (no alert wrapper).
func TestParseDecisionsFlatSchema(t *testing.T) {
	flat := []byte(`[{"id":9,"origin":"cscli","type":"ban","scope":"Ip","value":"7.7.7.7","duration":"1h"}]`)
	entries, err := parseDecisions(flat, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Value != "7.7.7.7" || entries[0].NativeID != "9" {
		t.Fatalf("flat-schema parse = %+v", entries)
	}
}

func TestListBansViaRunner(t *testing.T) {
	f := exec.NewFake()
	f.Set(string(fixture(t)), 0, "cscli", "decisions", "list", "-o", "json")
	entries, err := New(f).ListBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("ListBans = %d entries", len(entries))
	}
}

func TestBanDryRun(t *testing.T) {
	f := exec.NewFake()
	res, err := New(f).Ban(context.Background(), model.ActionRequest{
		Value: "5.6.7.8", Scope: model.ScopeIP, Duration: 4 * time.Hour, Reason: "test", DryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("dry-run must not report a change")
	}
	want := "cscli decisions add --ip 5.6.7.8 --duration 4h0m0s --type ban --reason test"
	if len(res.Commands) != 1 || res.Commands[0] != want {
		t.Fatalf("commands = %v, want %q", res.Commands, want)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

func TestBanExecutes(t *testing.T) {
	f := exec.NewFake()
	f.Set("", 0, "cscli", "decisions", "add", "--ip", "5.6.7.8", "--type", "ban")
	res, err := New(f).Ban(context.Background(), model.ActionRequest{Value: "5.6.7.8", Scope: model.ScopeIP})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("executed ban should report a change")
	}
}

func TestUnbanByID(t *testing.T) {
	f := exec.NewFake()
	res, err := New(f).Unban(context.Background(), model.Entry{Value: "1.2.3.4", NativeID: "4"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Commands) != 1 || res.Commands[0] != "cscli decisions delete --id 4" {
		t.Fatalf("unban command = %v", res.Commands)
	}
}
