// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

// Package audit writes an append-only, machine-readable trail of every mutating
// action. Records are JSON lines; all string fields are sanitized to strip
// control characters so a crafted reason/value cannot forge or break log lines.
package audit

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"
)

// DefaultPath is the canonical audit log location.
const DefaultPath = "/var/log/omniban.log"

// Record is one audit line.
type Record struct {
	Timestamp string `json:"ts"`
	User      string `json:"user"`
	Action    string `json:"action"`
	Backend   string `json:"backend,omitempty"`
	Value     string `json:"value,omitempty"`
	Scope     string `json:"scope,omitempty"`
	Direction string `json:"direction,omitempty"`
	Duration  string `json:"duration,omitempty"`
	Reason    string `json:"reason,omitempty"`
	External  bool   `json:"external,omitempty"`
	DryRun    bool   `json:"dry_run,omitempty"`
	Result    string `json:"result,omitempty"`
	NativeID  string `json:"native_id,omitempty"`
}

// Logger appends sanitized records to a file. A Logger with an empty path is a
// no-op (used in dry-run or when the trail is unavailable).
type Logger struct {
	mu   sync.Mutex
	path string
	now  func() time.Time
}

// New returns a Logger writing to path. Pass "" to disable.
func New(path string) *Logger { return &Logger{path: path, now: time.Now} }

// Write sanitizes and appends rec as a single JSON line (0640, root:adm
// convention). It stamps the timestamp and user when unset.
func (l *Logger) Write(rec Record) (err error) {
	if l == nil || l.path == "" {
		return nil
	}
	if rec.Timestamp == "" {
		rec.Timestamp = l.now().UTC().Format(time.RFC3339)
	}
	if rec.User == "" {
		rec.User = currentUser()
	}
	rec = sanitizeRecord(rec)

	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	_, err = f.Write(append(line, '\n'))
	return err
}

// Sanitize strips CR, LF, ESC, and other C0 control characters from s.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func sanitizeRecord(r Record) Record {
	r.User = Sanitize(r.User)
	r.Action = Sanitize(r.Action)
	r.Backend = Sanitize(r.Backend)
	r.Value = Sanitize(r.Value)
	r.Scope = Sanitize(r.Scope)
	r.Direction = Sanitize(r.Direction)
	r.Duration = Sanitize(r.Duration)
	r.Reason = Sanitize(r.Reason)
	r.Result = Sanitize(r.Result)
	r.NativeID = Sanitize(r.NativeID)
	return r
}

func currentUser() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "unknown"
}
