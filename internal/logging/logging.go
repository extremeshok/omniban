// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

// Package logging configures the process diagnostic logger (slog). This is
// distinct from the audit trail in internal/audit, which records mutations.
package logging

import (
	"io"
	"log/slog"
	"strings"
)

// Setup builds a slog.Logger writing to w. level is one of
// debug|info|warn|error (default info); jsonFormat selects JSON vs text.
func Setup(w io.Writer, level string, jsonFormat bool) *slog.Logger {
	opts := &slog.HandlerOptions{Level: parseLevel(level)}
	var h slog.Handler
	if jsonFormat {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	return slog.New(h)
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
