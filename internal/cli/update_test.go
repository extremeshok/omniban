// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package cli

import (
	"context"
	"testing"
	"time"

	"github.com/extremeshok/omniban/internal/config"
	"github.com/extremeshok/omniban/internal/exec"
)

func TestIsPackageManaged_StampedPackage(t *testing.T) {
	a := &app{installSource: "package", runner: exec.NewFake()}
	if !a.isPackageManaged(context.Background()) {
		t.Fatal("a package-stamped build must be reported as package-managed")
	}
}

func TestIsPackageManaged_DpkgOwned(t *testing.T) {
	exe, err := resolveExe()
	if err != nil {
		t.Fatal(err)
	}
	f := exec.NewFake()
	f.Set("omniban: "+exe, 0, "dpkg", "-S", exe) // dpkg owns the path
	a := &app{installSource: "", runner: f}
	if !a.isPackageManaged(context.Background()) {
		t.Fatal("a dpkg-owned binary must be reported as package-managed")
	}
}

func TestIsPackageManaged_NotOwned(t *testing.T) {
	// FakeRunner errors on unregistered commands, mimicking dpkg/rpm reporting
	// the path as not owned (or being absent).
	a := &app{installSource: "", runner: exec.NewFake()}
	if a.isPackageManaged(context.Background()) {
		t.Fatal("a standalone binary not owned by dpkg/rpm must not be package-managed")
	}
}

func TestUpdateCacheRoundTripAndThrottle(t *testing.T) {
	dir := t.TempDir()
	a := &app{
		cfg:     config.Config{StateDir: dir, UpdateCheck: true},
		runner:  exec.NewFake(),
		version: "v1.0.0",
	}

	a.saveUpdateCache(updateCache{LastCheckUnix: time.Now().Unix(), Latest: "v9.9.9"})
	if got := a.loadUpdateCache(); got.Latest != "v9.9.9" {
		t.Fatalf("cache round-trip: got %q", got.Latest)
	}

	// A fresh cache is served without any network call.
	if got := a.cachedOrFreshLatest(context.Background()); got != "v9.9.9" {
		t.Fatalf("fresh cache should be reused: got %q", got)
	}
}
