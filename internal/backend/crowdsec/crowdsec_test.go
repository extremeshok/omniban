// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package crowdsec

import (
	"context"
	"strings"
	"testing"

	"github.com/extremeshok/omniban/internal/exec"
)

func TestDetectNotInstalled(t *testing.T) {
	f := exec.NewFake()
	f.Missing = []string{"cscli"}
	d, err := New(f).Detect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d.Installed {
		t.Fatal("cscli absent but reported installed")
	}
}

func TestDetectActiveNoBouncer(t *testing.T) {
	f := exec.NewFake()
	f.Set("v1.6.4", 0, "cscli", "version")
	f.Set("active", 0, "systemctl", "is-active", "crowdsec")
	f.Set("[]", 0, "cscli", "bouncers", "list", "-o", "json")

	d, err := New(f).Detect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !d.Installed || !d.Active {
		t.Fatalf("want installed+active, got %+v", d)
	}
	if d.Enforcing {
		t.Fatal("no bouncer registered but reported enforcing")
	}
	if len(d.Warnings) == 0 || !strings.Contains(d.Warnings[0], "bouncer") {
		t.Fatalf("expected no-bouncer warning, got %v", d.Warnings)
	}
	if d.Version != "v1.6.4" {
		t.Fatalf("version = %q", d.Version)
	}
}

func TestDetectActiveWithBouncer(t *testing.T) {
	f := exec.NewFake()
	f.Set("v1.6.4", 0, "cscli", "version")
	f.Set("active", 0, "systemctl", "is-active", "crowdsec")
	f.Set(`[{"name":"cs-firewall-bouncer"}]`, 0, "cscli", "bouncers", "list", "-o", "json")

	d, err := New(f).Detect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !d.Enforcing {
		t.Fatal("bouncer present but not reported enforcing")
	}
	if len(d.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", d.Warnings)
	}
}
