// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package suricata

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

func TestListBans(t *testing.T) {
	b := New(exec.NewFake())
	b.stateFile = filepath.Join("testdata", "omniban-deny.lst")

	got, err := b.ListBans(context.Background())
	if err != nil {
		t.Fatalf("ListBans: %v", err)
	}

	want := []model.Entry{
		{Value: "198.51.100.7", Family: model.FamilyIPv4, Scope: model.ScopeIP, Kind: model.KindBan, Direction: model.DirInbound, Origin: model.OriginSuricata, Backend: "suricata", Detail: "omniban-deny", Raw: "198.51.100.7"},
		{Value: "203.0.113.42", Family: model.FamilyIPv4, Scope: model.ScopeIP, Kind: model.KindBan, Direction: model.DirInbound, Origin: model.OriginSuricata, Backend: "suricata", Detail: "omniban-deny", Raw: "203.0.113.42"},
		{Value: "2001:db8::1", Family: model.FamilyIPv6, Scope: model.ScopeIP, Kind: model.KindBan, Direction: model.DirInbound, Origin: model.OriginSuricata, Backend: "suricata", Detail: "omniban-deny", Raw: "2001:db8::1"},
		{Value: "192.0.2.200", Family: model.FamilyIPv4, Scope: model.ScopeIP, Kind: model.KindBan, Direction: model.DirInbound, Origin: model.OriginSuricata, Backend: "suricata", Detail: "omniban-deny", Raw: "192.0.2.200"},
	}

	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("entry %d:\n got %+v\nwant %+v", i, got[i], want[i])
		}
	}
}

func TestListBansMissingFile(t *testing.T) {
	b := New(exec.NewFake())
	b.stateFile = filepath.Join(t.TempDir(), "absent.lst")

	got, err := b.ListBans(context.Background())
	if err != nil {
		t.Fatalf("ListBans on missing file: %v", err)
	}
	if got != nil {
		t.Fatalf("missing file should yield nil, got %+v", got)
	}
}

func TestBanDryRun(t *testing.T) {
	f := exec.NewFake()
	b := New(f)

	res, err := b.Ban(context.Background(), model.ActionRequest{Value: "198.51.100.7", Scope: model.ScopeIP, DryRun: true})
	if err != nil {
		t.Fatalf("Ban dry-run: %v", err)
	}

	wantCmd := "suricatasc -c dataset-add omniban-deny ip 198.51.100.7 /var/run/suricata/command.socket"
	if len(res.Commands) != 1 || res.Commands[0] != wantCmd {
		t.Errorf("commands = %v, want [%q]", res.Commands, wantCmd)
	}
	if !res.DryRun || res.Changed {
		t.Errorf("dry-run flags wrong: DryRun=%v Changed=%v", res.DryRun, res.Changed)
	}
	if res.Message != "dry-run: not executed" {
		t.Errorf("message = %q", res.Message)
	}
	if len(f.Calls) != 0 {
		t.Errorf("dry-run must not invoke the runner, got calls: %v", f.Calls)
	}
}

func TestBanExecuted(t *testing.T) {
	f := exec.NewFake()
	args := []string{"-c", "dataset-add omniban-deny ip 203.0.113.42", "/var/run/suricata/command.socket"}
	f.Set("", 0, "suricatasc", args...)
	b := New(f)

	res, err := b.Ban(context.Background(), model.ActionRequest{Value: "203.0.113.42", Scope: model.ScopeIP})
	if err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if !res.Changed || res.DryRun {
		t.Errorf("executed flags wrong: Changed=%v DryRun=%v", res.Changed, res.DryRun)
	}
	wantKey := exec.Key("suricatasc", args)
	if len(f.Calls) != 1 || f.Calls[0] != wantKey {
		t.Errorf("calls = %v, want [%q]", f.Calls, wantKey)
	}
}

func TestUnbanExecuted(t *testing.T) {
	f := exec.NewFake()
	args := []string{"-c", "dataset-remove omniban-deny ip 2001:db8::1", "/var/run/suricata/command.socket"}
	f.Set("", 0, "suricatasc", args...)
	b := New(f)

	res, err := b.Unban(context.Background(), model.Entry{Value: "2001:db8::1"}, false)
	if err != nil {
		t.Fatalf("Unban: %v", err)
	}
	wantCmd := "suricatasc -c dataset-remove omniban-deny ip 2001:db8::1 /var/run/suricata/command.socket"
	if len(res.Commands) != 1 || res.Commands[0] != wantCmd {
		t.Errorf("commands = %v, want [%q]", res.Commands, wantCmd)
	}
	if !res.Changed {
		t.Errorf("Unban should set Changed")
	}
	wantKey := exec.Key("suricatasc", args)
	if len(f.Calls) != 1 || f.Calls[0] != wantKey {
		t.Errorf("calls = %v, want [%q]", f.Calls, wantKey)
	}
}

func TestUnbanDryRun(t *testing.T) {
	f := exec.NewFake()
	b := New(f)

	res, err := b.Unban(context.Background(), model.Entry{Value: "192.0.2.200"}, true)
	if err != nil {
		t.Fatalf("Unban dry-run: %v", err)
	}
	wantCmd := "suricatasc -c dataset-remove omniban-deny ip 192.0.2.200 /var/run/suricata/command.socket"
	if len(res.Commands) != 1 || res.Commands[0] != wantCmd {
		t.Errorf("commands = %v, want [%q]", res.Commands, wantCmd)
	}
	if res.Changed {
		t.Errorf("dry-run must not set Changed")
	}
	if len(f.Calls) != 0 {
		t.Errorf("dry-run must not invoke the runner, got calls: %v", f.Calls)
	}
}
