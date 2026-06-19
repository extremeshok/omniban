// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/extremeshok/omniban/internal/config"
	"github.com/extremeshok/omniban/internal/exec"
	"github.com/extremeshok/omniban/internal/selfupdate"
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

// fakeReleases serves a releases/latest payload reporting the given tag.
func fakeReleases(t *testing.T, tag string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+selfupdate.Repo+"/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"tag_name":%q,"assets":[]}`, tag)
	})
	return httptest.NewServer(mux)
}

func TestUpdateCheckExitCode(t *testing.T) {
	srv := fakeReleases(t, "v9.9.9")
	defer srv.Close()
	old := selfupdate.APIBase
	selfupdate.APIBase = srv.URL
	defer func() { selfupdate.APIBase = old }()

	// Newer release available → --check returns an error exposing exit code 10.
	a := &app{out: &bytes.Buffer{}, runner: exec.NewFake(), version: "v1.0.0", cfg: config.Config{StateDir: t.TempDir()}}
	err := a.runUpdate(context.Background(), true)
	var coder interface{ ExitCode() int }
	if !errors.As(err, &coder) || coder.ExitCode() != 10 {
		t.Fatalf("check should exit 10 when an update is available, got %v", err)
	}

	// Already current → no error (exit 0).
	a2 := &app{out: &bytes.Buffer{}, runner: exec.NewFake(), version: "v9.9.9", cfg: config.Config{StateDir: t.TempDir()}}
	if err := a2.runUpdate(context.Background(), true); err != nil {
		t.Fatalf("check should return nil when up to date, got %v", err)
	}
}
