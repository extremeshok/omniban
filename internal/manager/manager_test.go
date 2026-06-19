// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package manager

import (
	"strings"
	"testing"

	"github.com/extremeshok/omniban/internal/backend"
	"github.com/extremeshok/omniban/internal/config"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/model"
)

func fw(name string, active bool) Status {
	return Status{
		Name:      name,
		Layer:     model.LayerFirewall,
		Detection: backend.Detection{Installed: true, Active: active},
	}
}

func TestManualTargetPriority(t *testing.T) {
	m := New(config.Default(), exec.NewFake())
	statuses := []Status{fw("ufw", true), fw("firewalld", true), fw("iptables", true)}
	if got := m.ManualTarget(statuses); got != "firewalld" {
		t.Fatalf("ManualTarget priority = %q, want firewalld", got)
	}
}

func TestManualTargetConfigOverride(t *testing.T) {
	cfg := config.Default()
	cfg.ManualBanBackend = "ufw"
	m := New(cfg, exec.NewFake())
	statuses := []Status{fw("ufw", true), fw("firewalld", true)}
	if got := m.ManualTarget(statuses); got != "ufw" {
		t.Fatalf("ManualTarget override = %q, want ufw", got)
	}
}

func TestManualTargetConfigInactiveFallsBack(t *testing.T) {
	cfg := config.Default()
	cfg.ManualBanBackend = "csf" // configured but not active
	m := New(cfg, exec.NewFake())
	statuses := []Status{fw("ufw", true)}
	if got := m.ManualTarget(statuses); got != "ufw" {
		t.Fatalf("ManualTarget fallback = %q, want ufw", got)
	}
}

func TestCrossWarningsMultipleFirewalls(t *testing.T) {
	m := New(config.Default(), exec.NewFake())
	statuses := []Status{fw("ufw", true), fw("firewalld", true)}
	warns := m.CrossWarnings(statuses)
	if len(warns) == 0 || !strings.Contains(warns[0], "multiple active firewall") {
		t.Fatalf("expected multiple-firewall warning, got %v", warns)
	}
}

func TestCrossWarningsNoFirewall(t *testing.T) {
	m := New(config.Default(), exec.NewFake())
	warns := m.CrossWarnings([]Status{{Name: "fail2ban", Layer: model.LayerIDS, Detection: backend.Detection{Installed: true, Active: true}}})
	if len(warns) == 0 || !strings.Contains(warns[0], "no active firewall") {
		t.Fatalf("expected no-firewall warning, got %v", warns)
	}
}

func TestDisabledBackendsFiltered(t *testing.T) {
	cfg := config.Default()
	cfg.DisabledBackends = []string{"hosts", "blackhole"}
	m := New(cfg, exec.NewFake())
	for _, b := range m.Backends() {
		if b.Name() == "hosts" || b.Name() == "blackhole" {
			t.Fatalf("disabled backend %q still present", b.Name())
		}
	}
}
