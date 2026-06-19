// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaultsWhenFileMissing(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogFile != DefaultLogFile || cfg.StateDir != DefaultStateDir {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
}

func TestLoadFileOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := "manual_ban_backend: ufw\nrefresh_seconds: 15\ndisabled_backends:\n  - hosts\n"
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ManualBanBackend != "ufw" || cfg.RefreshSeconds != 15 {
		t.Fatalf("file overrides not applied: %+v", cfg)
	}
	if len(cfg.DisabledBackends) != 1 || cfg.DisabledBackends[0] != "hosts" {
		t.Fatalf("disabled_backends = %v", cfg.DisabledBackends)
	}
}

func TestValidate(t *testing.T) {
	bad := Default()
	bad.LogLevel = "loud"
	if err := bad.Validate(); err == nil {
		t.Fatal("invalid log level should fail validation")
	}
	bad = Default()
	bad.RefreshSeconds = -1
	if err := bad.Validate(); err == nil {
		t.Fatal("negative refresh should fail validation")
	}
}

func TestIsForeignResource(t *testing.T) {
	for _, tc := range []struct {
		name    string
		foreign bool
	}{
		{"f2b-sshd", true},
		{"crowdsec-blacklists", true},
		{"fw-public-allow", true},
		{"omniban-deny4", false},
		{"omniban", false},
		{"random-set", false},
	} {
		if got := IsForeignResource(tc.name); got != tc.foreign {
			t.Errorf("IsForeignResource(%q) = %v, want %v", tc.name, got, tc.foreign)
		}
	}
}
