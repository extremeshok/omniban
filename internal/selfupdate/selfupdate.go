// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

// Package selfupdate checks GitHub releases for a newer omniban and applies an
// update in place: it downloads the release tarball for the running OS/arch,
// verifies it against the release's checksums.txt (SHA-256), and atomically
// swaps the running binary, keeping a .bak for rollback.
//
// Self-update is only ever used for standalone-binary installs. Package-manager
// builds (.deb/.rpm) stamp installSource=package; callers must check Managed()
// first and defer to apt/dnf.
package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

const (
	// Repo is the GitHub repository self-update queries for releases.
	Repo = "extremeshok/omniban"
	// PackageSource is the installSource build stamp for .deb/.rpm artifacts.
	PackageSource = "package"

	binaryName   = "omniban"
	checksumName = "checksums.txt"
	maxDownload  = 100 << 20 // 100 MiB cap on any single download.
)

// Managed reports whether this build is owned by a distro package manager, in
// which case self-update must defer to apt/dnf rather than swap the binary.
func Managed(installSource string) bool { return installSource == PackageSource }

// Newer reports whether latest is a strictly higher semver than current. A
// non-semver current (e.g. an unstamped "dev" build) is never considered older,
// so dev builds do not nag about updates.
func Newer(latest, current string) bool {
	l, c := normalize(latest), normalize(current)
	return semver.IsValid(l) && semver.IsValid(c) && semver.Compare(c, l) < 0
}

// AssetName is the resolved release tarball filename for the running OS/arch, or
// "" when the latest release carries no matching asset.
func (s Status) AssetName() string { return s.tarballName }

// Status is the outcome of a version check.
type Status struct {
	Current   string `json:"current"`
	Latest    string `json:"latest"`
	Available bool   `json:"update_available"`

	// Resolved release assets for the running OS/arch (empty when not found).
	tarballURL  string
	tarballName string
	checksumURL string
}

// ghRelease is the subset of the GitHub release API we consume.
type ghRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// httpClient returns the supplied client or a sane default with a timeout.
func httpClient(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// APIBase is the GitHub API root; overridable in tests.
var APIBase = "https://api.github.com"

// Check queries the latest release and compares it to current. current is the
// stamped build version (e.g. "v1.2.3" or "dev"). A non-semver current (a dev
// build) never reports Available=true but still surfaces Latest.
func Check(ctx context.Context, client *http.Client, current string) (Status, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/latest", APIBase, Repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Status{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "omniban-selfupdate")

	resp, err := httpClient(client).Do(req)
	if err != nil {
		return Status{}, fmt.Errorf("query latest release: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return Status{}, fmt.Errorf("query latest release: unexpected status %s", resp.Status)
	}

	var rel ghRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel); err != nil {
		return Status{}, fmt.Errorf("decode release: %w", err)
	}
	latest := strings.TrimSpace(rel.TagName)
	if latest == "" {
		return Status{}, fmt.Errorf("release has no tag_name")
	}

	st := Status{Current: current, Latest: latest, Available: Newer(latest, current)}

	want := assetName(latest)
	for _, a := range rel.Assets {
		switch a.Name {
		case want:
			st.tarballURL, st.tarballName = a.URL, a.Name
		case checksumName:
			st.checksumURL = a.URL
		}
	}
	return st, nil
}

// Apply downloads the resolved release tarball, verifies its SHA-256 against the
// release checksums file, extracts the omniban binary, and atomically replaces
// the executable at targetPath, leaving targetPath+".bak" for rollback.
func Apply(ctx context.Context, client *http.Client, st Status, targetPath string) error {
	if st.tarballURL == "" {
		return fmt.Errorf("no release asset for %s/%s in %s", runtime.GOOS, runtime.GOARCH, st.Latest)
	}
	if st.checksumURL == "" {
		return fmt.Errorf("release %s has no %s to verify against", st.Latest, checksumName)
	}

	tarGz, err := download(ctx, client, st.tarballURL)
	if err != nil {
		return fmt.Errorf("download %s: %w", st.tarballName, err)
	}
	sums, err := download(ctx, client, st.checksumURL)
	if err != nil {
		return fmt.Errorf("download %s: %w", checksumName, err)
	}

	want, ok := checksumFor(string(sums), st.tarballName)
	if !ok {
		return fmt.Errorf("%s has no entry for %s", checksumName, st.tarballName)
	}
	got := sha256.Sum256(tarGz)
	if hex.EncodeToString(got[:]) != want {
		return fmt.Errorf("checksum mismatch for %s: refusing to apply", st.tarballName)
	}

	bin, err := extractBinary(tarGz)
	if err != nil {
		return err
	}
	return swap(targetPath, bin)
}

// download fetches a URL into memory, bounded by maxDownload.
func download(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "omniban-selfupdate")
	resp, err := httpClient(client).Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxDownload))
}

// extractBinary returns the omniban binary from a release .tar.gz.
func extractBinary(tarGz []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tarGz))
	if err != nil {
		return nil, fmt.Errorf("open gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || filepath.Base(hdr.Name) != binaryName {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxDownload))
		if err != nil {
			return nil, fmt.Errorf("read %s from tar: %w", binaryName, err)
		}
		return b, nil
	}
	return nil, fmt.Errorf("tarball does not contain %q", binaryName)
}

// swap atomically replaces the file at path with newBin, backing the previous
// binary up to path+".bak" so a failed deploy can be rolled back. Both files
// live in the same directory so the final rename is atomic.
func swap(path string, newBin []byte) error {
	dir := filepath.Dir(path)
	mode := os.FileMode(0o755)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}

	tmp, err := os.CreateTemp(dir, ".omniban-update-*")
	if err != nil {
		return fmt.Errorf("create staging file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if _, err := tmp.Write(newBin); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write staging file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close staging file: %w", err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		cleanup()
		return fmt.Errorf("chmod staging file: %w", err)
	}

	bak := path + ".bak"
	if err := os.Rename(path, bak); err != nil {
		cleanup()
		return fmt.Errorf("back up current binary: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		// Roll back to the previous binary.
		_ = os.Rename(bak, path)
		cleanup()
		return fmt.Errorf("install new binary: %w", err)
	}
	return nil
}

// assetName is the release tarball name for the running OS/arch, matching the
// goreleaser archive name_template (omniban_<version>_<os>_<arch>.tar.gz).
func assetName(version string) string {
	return fmt.Sprintf("%s_%s_%s_%s.tar.gz", binaryName, strings.TrimPrefix(version, "v"), runtime.GOOS, runtime.GOARCH)
}

// checksumFor returns the hex SHA-256 listed for name in a checksums.txt body
// ("<hex>  <name>" per line).
func checksumFor(body, name string) (string, bool) {
	for _, line := range strings.Split(body, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == name {
			return fields[0], true
		}
	}
	return "", false
}

// normalize ensures a leading "v" so semver functions accept the string.
func normalize(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}
