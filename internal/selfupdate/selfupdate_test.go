// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestManaged(t *testing.T) {
	if !Managed(PackageSource) {
		t.Fatal("package build must be reported as managed")
	}
	for _, s := range []string{"", "source", "binary", "homebrew"} {
		if Managed(s) {
			t.Errorf("installSource %q must not be managed", s)
		}
	}
}

func TestNormalizeAndChecksumFor(t *testing.T) {
	if got := normalize("1.2.3"); got != "v1.2.3" {
		t.Errorf("normalize: got %q", got)
	}
	if got := normalize("v1.2.3"); got != "v1.2.3" {
		t.Errorf("normalize: got %q", got)
	}
	body := "abc123  omniban_1.0.0_linux_amd64.tar.gz\ndef456  omniban_1.0.0_linux_arm64.tar.gz\n"
	if sum, ok := checksumFor(body, "omniban_1.0.0_linux_arm64.tar.gz"); !ok || sum != "def456" {
		t.Errorf("checksumFor: got %q ok=%v", sum, ok)
	}
	if _, ok := checksumFor(body, "missing.tar.gz"); ok {
		t.Error("checksumFor matched a missing entry")
	}
}

// releaseHandler serves a minimal GitHub releases/latest payload whose assets
// point back at the same test server.
func releaseHandler(t *testing.T, srvURL, tag string) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+Repo+"/releases/latest", func(w http.ResponseWriter, _ *http.Request) {
		asset := assetName(tag)
		fmt.Fprintf(w, `{"tag_name":%q,"assets":[
			{"name":%q,"browser_download_url":%q},
			{"name":%q,"browser_download_url":%q}]}`,
			tag,
			asset, srvURL+"/dl/"+asset,
			checksumName, srvURL+"/dl/"+checksumName)
	})
	return mux
}

func TestCheck(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		releaseHandler(t, srv.URL, "v2.0.0").ServeHTTP(w, r)
	}))
	defer srv.Close()

	old := APIBase
	APIBase = srv.URL
	defer func() { APIBase = old }()

	cases := []struct {
		current   string
		available bool
	}{
		{"v1.0.0", true},
		{"v2.0.0", false},
		{"v2.1.0", false},
		{"dev", false}, // unstamped build never claims an update
	}
	for _, tc := range cases {
		st, err := Check(context.Background(), srv.Client(), tc.current)
		if err != nil {
			t.Fatalf("Check(%s): %v", tc.current, err)
		}
		if st.Available != tc.available {
			t.Errorf("Check(%s): Available=%v want %v", tc.current, st.Available, tc.available)
		}
		if st.Latest != "v2.0.0" {
			t.Errorf("Check(%s): Latest=%q", tc.current, st.Latest)
		}
		if st.tarballURL == "" || st.checksumURL == "" {
			t.Errorf("Check(%s): unresolved asset URLs", tc.current)
		}
	}
}

// makeTarGz builds a release-style .tar.gz embedding the omniban binary.
func makeTarGz(t *testing.T, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: binaryName, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestApplySwapsBinary(t *testing.T) {
	newContent := []byte("FAKE-NEW-OMNIBAN-BINARY\n")
	tarGz := makeTarGz(t, newContent)
	sum := sha256.Sum256(tarGz)
	asset := assetName("v3.1.0")

	mux := http.NewServeMux()
	mux.HandleFunc("/dl/"+asset, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(tarGz) })
	mux.HandleFunc("/dl/"+checksumName, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", hex.EncodeToString(sum[:]), asset)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	target := filepath.Join(dir, "omniban")
	if err := os.WriteFile(target, []byte("OLD-BINARY\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	st := Status{
		Latest:      "v3.1.0",
		tarballURL:  srv.URL + "/dl/" + asset,
		tarballName: asset,
		checksumURL: srv.URL + "/dl/" + checksumName,
	}
	if err := Apply(context.Background(), srv.Client(), st, target); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, newContent) {
		t.Fatalf("target not replaced: %q err=%v", got, err)
	}
	bak, err := os.ReadFile(target + ".bak")
	if err != nil || string(bak) != "OLD-BINARY\n" {
		t.Fatalf("backup not kept: %q err=%v", bak, err)
	}
	if fi, err := os.Stat(target); err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode not preserved: %v err=%v", fi.Mode(), err)
	}
}

func TestApplyRejectsBadChecksum(t *testing.T) {
	tarGz := makeTarGz(t, []byte("whatever\n"))
	asset := assetName("v3.1.0")

	mux := http.NewServeMux()
	mux.HandleFunc("/dl/"+asset, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(tarGz) })
	mux.HandleFunc("/dl/"+checksumName, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", "deadbeef", asset) // wrong hash
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := t.TempDir()
	target := filepath.Join(dir, "omniban")
	if err := os.WriteFile(target, []byte("OLD\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	st := Status{
		Latest:      "v3.1.0",
		tarballURL:  srv.URL + "/dl/" + asset,
		tarballName: asset,
		checksumURL: srv.URL + "/dl/" + checksumName,
	}
	if err := Apply(context.Background(), srv.Client(), st, target); err == nil {
		t.Fatal("Apply must reject a checksum mismatch")
	}
	if got, _ := os.ReadFile(target); string(got) != "OLD\n" {
		t.Fatalf("target must be untouched on checksum failure, got %q", got)
	}
}
