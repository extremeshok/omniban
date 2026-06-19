// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitize(t *testing.T) {
	in := "evil\r\n\x1b[31mforged\x1b[0m\tline"
	got := Sanitize(in)
	if strings.ContainsAny(got, "\r\n\x1b") {
		t.Fatalf("Sanitize left control chars: %q", got)
	}
	if !strings.Contains(got, "forged") {
		t.Fatalf("Sanitize dropped content: %q", got)
	}
}

func TestWriteJSONLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "omniban.log")
	l := New(path)

	rec := Record{Action: "ban", Backend: "ufw", Value: "1.2.3.4", Reason: "bad\nactor"}
	if err := l.Write(rec); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(data))
	var out Record
	if err := json.Unmarshal([]byte(line), &out); err != nil {
		t.Fatalf("audit line is not valid JSON: %v (%q)", err, line)
	}
	if out.Timestamp == "" || out.User == "" {
		t.Fatalf("ts/user not stamped: %+v", out)
	}
	if strings.Contains(out.Reason, "\n") {
		t.Fatalf("reason not sanitized: %q", out.Reason)
	}
}

func TestNilLoggerIsNoop(t *testing.T) {
	var l *Logger
	if err := l.Write(Record{Action: "ban"}); err != nil {
		t.Fatalf("nil logger should be a no-op, got %v", err)
	}
	if err := New("").Write(Record{Action: "ban"}); err != nil {
		t.Fatalf("empty-path logger should be a no-op, got %v", err)
	}
}
