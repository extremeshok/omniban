// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package wazuh

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

// newBackend returns a Wazuh backend rooted at dir, using the given runner.
func newBackend(r exec.Runner, dir string) *Backend {
	return &Backend{r: r, dir: dir}
}

func TestListBans(t *testing.T) {
	b := newBackend(exec.NewFake(), "testdata")
	got, err := b.ListBans(context.Background())
	if err != nil {
		t.Fatalf("ListBans: %v", err)
	}
	// 198.51.100.7 was added then deleted; host-deny (192.0.2.99) is a different
	// program; 203.0.113.10 and the IPv6 add remain active.
	want := []struct {
		value  string
		family model.Family
		scope  model.Scope
	}{
		{"203.0.113.10", model.FamilyIPv4, model.ScopeIP},
		{"2001:db8::dead:beef", model.FamilyIPv6, model.ScopeIP},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		e := got[i]
		if e.Value != w.value {
			t.Errorf("entry %d value = %q, want %q", i, e.Value, w.value)
		}
		if e.Family != w.family {
			t.Errorf("entry %d family = %q, want %q", i, e.Family, w.family)
		}
		if e.Scope != w.scope {
			t.Errorf("entry %d scope = %q, want %q", i, e.Scope, w.scope)
		}
		if e.Kind != model.KindBan {
			t.Errorf("entry %d kind = %q, want %q", i, e.Kind, model.KindBan)
		}
		if e.Direction != model.DirInbound {
			t.Errorf("entry %d direction = %q, want %q", i, e.Direction, model.DirInbound)
		}
		if e.Origin != model.OriginWazuh {
			t.Errorf("entry %d origin = %q, want %q", i, e.Origin, model.OriginWazuh)
		}
		if e.Backend != string(model.OriginWazuh) {
			t.Errorf("entry %d backend = %q, want %q", i, e.Backend, model.OriginWazuh)
		}
		if e.Detail != arProgram {
			t.Errorf("entry %d detail = %q, want %q", i, e.Detail, arProgram)
		}
		if e.CreatedAt == nil {
			t.Errorf("entry %d CreatedAt = nil, want a parsed timestamp", i)
		}
	}
}

func TestListBansMissingLog(t *testing.T) {
	b := newBackend(exec.NewFake(), t.TempDir()) // no logs/active-responses.log
	got, err := b.ListBans(context.Background())
	if err != nil {
		t.Fatalf("ListBans on missing log: %v", err)
	}
	if got != nil {
		t.Fatalf("ListBans on missing log = %+v, want nil", got)
	}
}

func TestBanDryRun(t *testing.T) {
	f := exec.NewFake()
	b := newBackend(f, "/var/ossec")
	res, err := b.Ban(context.Background(), model.ActionRequest{Value: "203.0.113.10", DryRun: true})
	if err != nil {
		t.Fatalf("Ban dry-run: %v", err)
	}
	if res.Changed {
		t.Errorf("dry-run Changed = true, want false")
	}
	if !res.DryRun {
		t.Errorf("dry-run DryRun = false, want true")
	}
	if res.Message != "dry-run: not executed" {
		t.Errorf("dry-run Message = %q", res.Message)
	}
	if len(res.Commands) != 1 {
		t.Fatalf("dry-run Commands = %v, want 1 entry", res.Commands)
	}
	if want := "/var/ossec/active-response/bin/firewall-drop"; !strings.Contains(res.Commands[0], want) {
		t.Errorf("dry-run command %q does not mention script %q", res.Commands[0], want)
	}
	// The recorded command must carry the add request JSON for the value.
	if !strings.Contains(res.Commands[0], `"command":"add"`) ||
		!strings.Contains(res.Commands[0], `"srcip":"203.0.113.10"`) {
		t.Errorf("dry-run command %q missing the add/srcip JSON", res.Commands[0])
	}
	// Nothing must have been executed.
	if len(f.Calls) != 0 {
		t.Errorf("dry-run executed commands: %v", f.Calls)
	}
	if len(f.Inputs) != 0 {
		t.Errorf("dry-run wrote stdin: %v", f.Inputs)
	}
}

func TestBanExecuted(t *testing.T) {
	f := exec.NewFake()
	script := "/var/ossec/active-response/bin/firewall-drop"
	f.Set("", 0, script)
	b := newBackend(f, "/var/ossec")

	res, err := b.Ban(context.Background(), model.ActionRequest{Value: "203.0.113.10"})
	if err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if !res.Changed {
		t.Errorf("Changed = false, want true")
	}
	if res.DryRun {
		t.Errorf("DryRun = true, want false")
	}

	key := exec.Key(script, nil)
	if len(f.Calls) != 1 || f.Calls[0] != key {
		t.Fatalf("Calls = %v, want exactly [%q]", f.Calls, key)
	}
	assertRequest(t, f.Inputs[key], "add", "203.0.113.10")
}

func TestUnbanExecuted(t *testing.T) {
	f := exec.NewFake()
	script := "/var/ossec/active-response/bin/firewall-drop"
	f.Set("", 0, script)
	b := newBackend(f, "/var/ossec")

	e := model.Entry{Value: "2001:db8::dead:beef"}
	res, err := b.Unban(context.Background(), e, false)
	if err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if !res.Changed {
		t.Errorf("Changed = false, want true")
	}

	key := exec.Key(script, nil)
	if len(f.Calls) != 1 || f.Calls[0] != key {
		t.Fatalf("Calls = %v, want exactly [%q]", f.Calls, key)
	}
	assertRequest(t, f.Inputs[key], "delete", "2001:db8::dead:beef")
}

func TestUnbanDryRun(t *testing.T) {
	f := exec.NewFake()
	b := newBackend(f, "/var/ossec")
	res, err := b.Unban(context.Background(), model.Entry{Value: "198.51.100.7"}, true)
	if err != nil {
		t.Fatalf("Unban dry-run: %v", err)
	}
	if res.Changed {
		t.Errorf("dry-run Changed = true, want false")
	}
	if len(f.Calls) != 0 || len(f.Inputs) != 0 {
		t.Errorf("dry-run touched the runner: calls=%v inputs=%v", f.Calls, f.Inputs)
	}
}

// assertRequest verifies that stdin is the exact firewall-drop JSON request for
// the given command and source IP.
func assertRequest(t *testing.T, stdin, wantCmd, wantIP string) {
	t.Helper()
	if stdin == "" {
		t.Fatalf("no stdin recorded for the invocation")
	}
	var req arRequest
	if err := json.Unmarshal([]byte(stdin), &req); err != nil {
		t.Fatalf("stdin is not valid JSON (%v): %q", err, stdin)
	}
	if req.Version != 1 {
		t.Errorf("version = %d, want 1", req.Version)
	}
	if req.Origin.Name != "omniban" || req.Origin.Module != "omniban" {
		t.Errorf("origin = %+v, want name/module omniban", req.Origin)
	}
	if req.Command != wantCmd {
		t.Errorf("command = %q, want %q", req.Command, wantCmd)
	}
	if req.Parameters.Program != arProgram {
		t.Errorf("program = %q, want %q", req.Parameters.Program, arProgram)
	}
	if req.Parameters.Alert.Data.SrcIP != wantIP {
		t.Errorf("srcip = %q, want %q", req.Parameters.Alert.Data.SrcIP, wantIP)
	}
}
