// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

// Package config loads omniban settings from layered sources: built-in
// defaults, an optional YAML file, then OMNIBAN_-prefixed environment
// variables. CLI flags are applied by the caller on top of the loaded Config.
package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// Canonical filesystem locations.
const (
	DefaultConfigPath = "/etc/omniban/config.yaml"
	DefaultLogFile    = "/var/log/omniban.log"
	DefaultStateDir   = "/var/lib/omniban"
)

// Config is the file/env-backed settings for omniban. CLI-only switches
// (--dry-run, --json, --no-color) are not stored here.
type Config struct {
	// ManualBanBackend forces which firewall backend receives manual inbound
	// bans when several are active. Empty means auto-select by priority.
	ManualBanBackend string `koanf:"manual_ban_backend"`
	// LogFile is the audit-trail path.
	LogFile string `koanf:"log_file"`
	// StateDir holds the undo journal and persisted blackhole routes.
	StateDir string `koanf:"state_dir"`
	// RefreshSeconds is the TUI auto-refresh interval (0 = manual only).
	RefreshSeconds int `koanf:"refresh_seconds"`
	// AdminAllowlist is always added to the lockout-prevention protected set.
	AdminAllowlist []string `koanf:"admin_allowlist"`
	// DisabledBackends lists backend names to ignore even when detected.
	DisabledBackends []string `koanf:"disabled_backends"`
	// LogLevel for the diagnostic slog logger (debug|info|warn|error).
	LogLevel string `koanf:"log_level"`
	// UpdateCheck enables the passive "a newer version is available" notice on
	// standalone-binary installs. It has no effect on .deb/.rpm builds, which
	// defer to the distribution package manager.
	UpdateCheck bool `koanf:"update_check"`
}

// Default returns the built-in defaults.
func Default() Config {
	return Config{
		ManualBanBackend: "",
		LogFile:          DefaultLogFile,
		StateDir:         DefaultStateDir,
		RefreshSeconds:   0,
		LogLevel:         "info",
		UpdateCheck:      true,
	}
}

// Load builds a Config from defaults, the YAML file at path (if it exists), and
// OMNIBAN_-prefixed environment variables, in increasing order of precedence.
// A missing file is not an error.
func Load(path string) (Config, error) {
	k := koanf.New(".")

	if err := k.Load(confmap.Provider(defaultMap(), "."), nil); err != nil {
		return Config{}, fmt.Errorf("load defaults: %w", err)
	}

	if path != "" {
		if _, statErr := os.Stat(path); statErr == nil {
			if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
				return Config{}, fmt.Errorf("load config %s: %w", path, err)
			}
		} else if !os.IsNotExist(statErr) {
			return Config{}, fmt.Errorf("stat config %s: %w", path, statErr)
		}
	}

	envProvider := env.Provider("OMNIBAN_", ".", func(s string) string {
		return strings.ToLower(strings.TrimPrefix(s, "OMNIBAN_"))
	})
	if err := k.Load(envProvider, nil); err != nil {
		return Config{}, fmt.Errorf("load env: %w", err)
	}

	cfg := Default()
	if err := k.Unmarshal("", &cfg); err != nil {
		return Config{}, fmt.Errorf("unmarshal config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks invariants on the loaded configuration.
func (c Config) Validate() error {
	if c.LogFile == "" {
		return fmt.Errorf("log_file must not be empty")
	}
	if c.StateDir == "" {
		return fmt.Errorf("state_dir must not be empty")
	}
	if c.RefreshSeconds < 0 {
		return fmt.Errorf("refresh_seconds must not be negative")
	}
	switch strings.ToLower(c.LogLevel) {
	case "", "debug", "info", "warn", "warning", "error":
	default:
		return fmt.Errorf("invalid log_level %q", c.LogLevel)
	}
	return nil
}

func defaultMap() map[string]any {
	d := Default()
	return map[string]any{
		"manual_ban_backend": d.ManualBanBackend,
		"log_file":           d.LogFile,
		"state_dir":          d.StateDir,
		"refresh_seconds":    d.RefreshSeconds,
		"log_level":          d.LogLevel,
		"update_check":       d.UpdateCheck,
	}
}
