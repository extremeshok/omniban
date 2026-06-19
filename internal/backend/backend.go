// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

// Package backend defines the adapter contract every ban mechanism implements,
// plus shared detection helpers. Concrete adapters live in sub-packages; the
// registry that wires them together lives in internal/backend/all to avoid an
// import cycle.
package backend

import (
	"context"
	"errors"

	"github.com/extremeshok/omniban/internal/model"
)

// ErrNotImplemented is returned by operations a backend does not (yet) support.
var ErrNotImplemented = errors.New("operation not supported by this backend")

// Detection is the result of probing for a backend on the host.
type Detection struct {
	Installed bool     // binary/config present
	Active    bool     // service running (or, for kernel facilities, usable)
	Enforcing bool     // actually blocking traffic right now
	Version   string   // best-effort version string
	Warnings  []string // operational warnings (e.g. crowdsec running without a bouncer)
}

// Capabilities advertises what a backend can do, so the CLI/TUI and the manager
// can route actions and render accurate affordances.
type Capabilities struct {
	Layer      model.Layer
	Directions []model.Direction
	Scopes     []model.Scope

	CanBan         bool
	CanUnban       bool
	CanAllow       bool
	CanRemoveAllow bool
	CanEnable      bool

	RequiresReferenceRule bool // ipset: a set only drops if a rule references it
	SupportsCIDR          bool
	SupportsIPv6          bool
	SupportsExpiry        bool
}

// Backend is the contract implemented by every ban mechanism adapter.
type Backend interface {
	Name() string
	Capabilities() Capabilities
	Detect(ctx context.Context) (Detection, error)

	ListBans(ctx context.Context) ([]model.Entry, error)
	ListAllows(ctx context.Context) ([]model.Entry, error)

	Ban(ctx context.Context, req model.ActionRequest) (model.Result, error)
	Unban(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error)
	Allow(ctx context.Context, req model.ActionRequest) (model.Result, error)
	RemoveAllow(ctx context.Context, e model.Entry, dryRun bool) (model.Result, error)

	// Reload persists/applies pending changes (firewalld --reload, csf -r, ...).
	Reload(ctx context.Context) error
}
