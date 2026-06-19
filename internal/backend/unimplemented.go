// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package backend

import (
	"context"

	"github.com/extremeshok/omniban/internal/model"
)

// Unimplemented supplies default bodies for the data/mutation methods so an
// adapter need only implement the operations it actually supports. Embed it;
// each adapter still defines Name, Capabilities, and Detect.
type Unimplemented struct{}

// ListBans reports that the backend cannot list bans.
func (Unimplemented) ListBans(context.Context) ([]model.Entry, error) {
	return nil, ErrNotImplemented
}

// ListAllows reports that the backend cannot list allowlist entries.
func (Unimplemented) ListAllows(context.Context) ([]model.Entry, error) {
	return nil, ErrNotImplemented
}

// Ban reports that the backend cannot add a ban.
func (Unimplemented) Ban(context.Context, model.ActionRequest) (model.Result, error) {
	return model.Result{}, ErrNotImplemented
}

// Unban reports that the backend cannot remove a ban.
func (Unimplemented) Unban(context.Context, model.Entry, bool) (model.Result, error) {
	return model.Result{}, ErrNotImplemented
}

// Allow reports that the backend cannot add an allowlist entry.
func (Unimplemented) Allow(context.Context, model.ActionRequest) (model.Result, error) {
	return model.Result{}, ErrNotImplemented
}

// RemoveAllow reports that the backend cannot remove an allowlist entry.
func (Unimplemented) RemoveAllow(context.Context, model.Entry, bool) (model.Result, error) {
	return model.Result{}, ErrNotImplemented
}

// Reload is a no-op for backends with nothing to persist or apply.
func (Unimplemented) Reload(context.Context) error { return nil }
