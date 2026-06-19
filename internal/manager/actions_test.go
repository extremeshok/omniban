// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package manager

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/extremeshok/omniban/internal/config"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

const crowdsecDecisions = `[
  {"id":4,"origin":"crowdsec","type":"ban","scope":"Ip","value":"1.2.3.4","duration":"3h","scenario":"crowdsecurity/ssh-bf"},
  {"id":5,"origin":"cscli","type":"ban","scope":"Range","value":"10.0.0.0/24","duration":"23h","scenario":"manual"}
]`

func tempCfg(t *testing.T) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.LogFile = filepath.Join(t.TempDir(), "audit.log")
	cfg.StateDir = t.TempDir()
	return cfg
}

func TestListAllIncludesCrowdSec(t *testing.T) {
	f := exec.NewFake()
	f.Set(crowdsecDecisions, 0, "cscli", "decisions", "list", "-o", "json")
	m := New(tempCfg(t), f)

	entries, _, err := m.ListAll(context.Background(), model.KindBan)
	if err != nil {
		t.Fatal(err)
	}
	var found int
	for _, e := range entries {
		if e.Origin == model.OriginCrowdSec {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("expected 2 crowdsec bans in unified list, got %d (of %d total)", found, len(entries))
	}
}

func TestSearchCIDRContains(t *testing.T) {
	f := exec.NewFake()
	f.Set(crowdsecDecisions, 0, "cscli", "decisions", "list", "-o", "json")
	m := New(tempCfg(t), f)

	hits, _, err := m.Search(context.Background(), "10.0.0.5", true, model.KindBan)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Value != "10.0.0.0/24" {
		t.Fatalf("contains search = %+v", hits)
	}

	// Without --contains, a bare IP inside the range should not match.
	hits, _, _ = m.Search(context.Background(), "10.0.0.5", false, model.KindBan)
	if len(hits) != 0 {
		t.Fatalf("exact search should not match covering CIDR: %+v", hits)
	}
}

func TestBanViaCrowdSecDryRun(t *testing.T) {
	f := exec.NewFake()
	m := New(tempCfg(t), f)

	res, err := m.Ban(context.Background(), model.ActionRequest{
		Value: "5.6.7.8", Backend: "crowdsec", DryRun: true,
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed {
		t.Fatal("dry-run must not change")
	}
	if len(res.Commands) == 0 || !strings.Contains(res.Commands[0], "decisions add --ip 5.6.7.8") {
		t.Fatalf("ban command = %v", res.Commands)
	}
	if len(f.Calls) != 0 {
		t.Fatalf("dry-run must not invoke the runner: %v", f.Calls)
	}
}

func TestBanLockoutGuard(t *testing.T) {
	f := exec.NewFake()
	m := New(tempCfg(t), f)
	// 127.0.0.1 is always in the protected set; without --force this must fail.
	_, err := m.Ban(context.Background(), model.ActionRequest{Value: "127.0.0.1", Backend: "crowdsec", DryRun: true}, false)
	if err == nil {
		t.Fatal("banning loopback without --force should be refused")
	}
	if !strings.Contains(err.Error(), "refusing to ban") {
		t.Fatalf("unexpected error: %v", err)
	}
}
