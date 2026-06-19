// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package backend

import (
	"context"
	"os"
	"strings"

	"github.com/extremeshok/omniban/internal/exec"
)

// FirstInstalled returns the first candidate that resolves: bare names are
// looked up on PATH, paths containing a slash are checked on disk. Returns ""
// when none are present.
func FirstInstalled(r exec.Runner, candidates ...string) string {
	for _, c := range candidates {
		if strings.Contains(c, "/") {
			if FileExists(c) {
				return c
			}
			continue
		}
		if _, err := r.LookPath(c); err == nil {
			return c
		}
	}
	return ""
}

// ServiceActive reports whether a systemd unit is active. A missing systemctl
// or an inactive/unknown unit both yield false.
func ServiceActive(ctx context.Context, r exec.Runner, unit string) bool {
	res, _ := r.Run(ctx, "systemctl", "is-active", unit)
	return strings.TrimSpace(res.Out()) == "active"
}

// FileExists reports whether path exists.
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// FirstLine returns the first non-empty line of s, trimmed.
func FirstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}
