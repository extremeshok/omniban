// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package exec

import (
	"context"
	"testing"
)

func TestKey(t *testing.T) {
	if got := Key("nft", []string{"-j", "list", "ruleset"}); got != "nft -j list ruleset" {
		t.Fatalf("Key = %q", got)
	}
	if got := Key("ip", nil); got != "ip" {
		t.Fatalf("Key no-args = %q", got)
	}
}

func TestFakeRunner(t *testing.T) {
	f := NewFake()
	f.Set("active", 0, "systemctl", "is-active", "crowdsec")

	res, err := f.Run(context.Background(), "systemctl", "is-active", "crowdsec")
	if err != nil {
		t.Fatal(err)
	}
	if res.Out() != "active" {
		t.Fatalf("Out = %q", res.Out())
	}
	if len(f.Calls) != 1 || f.Calls[0] != "systemctl is-active crowdsec" {
		t.Fatalf("Calls = %v", f.Calls)
	}

	if _, err := f.Run(context.Background(), "unregistered"); err == nil {
		t.Fatal("unregistered command should error")
	}
}

func TestFakeRunnerLookPath(t *testing.T) {
	f := NewFake()
	f.Missing = []string{"cscli"}
	if _, err := f.LookPath("cscli"); err == nil {
		t.Fatal("missing binary should not resolve")
	}
	if _, err := f.LookPath("nft"); err != nil {
		t.Fatalf("present binary should resolve: %v", err)
	}
}

func TestFakeRunnerNonZeroExit(t *testing.T) {
	f := NewFake()
	f.Set("inactive", 3, "systemctl", "is-active", "ufw")
	res, err := f.Run(context.Background(), "systemctl", "is-active", "ufw")
	if err == nil {
		t.Fatal("non-zero exit should return an error")
	}
	if res.ExitCode != 3 || res.Out() != "inactive" {
		t.Fatalf("res = %+v", res)
	}
}
