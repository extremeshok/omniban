// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/extremeshok/omniban/internal/model"
	"github.com/extremeshok/omniban/internal/validate"
)

// --- list ------------------------------------------------------------------

func (a *app) listCmd() *cobra.Command {
	var kind, origin, backend, direction string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List bans (or allows) across all backends, source- and direction-labeled",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			k := model.KindBan
			if strings.EqualFold(kind, "allow") {
				k = model.KindAllow
			}
			entries, warns, err := a.mgr.ListAll(cmd.Context(), k)
			if err != nil {
				return err
			}
			entries = filterEntries(entries, origin, backend, direction)
			return a.renderEntries(entries, warns)
		},
	}
	cmd.Flags().StringVar(&kind, "kind", "ban", "ban|allow")
	cmd.Flags().StringVar(&origin, "origin", "", "filter by origin (e.g. fail2ban, crowdsec)")
	cmd.Flags().StringVar(&backend, "backend", "", "filter by reporting backend")
	cmd.Flags().StringVar(&direction, "direction", "", "filter by direction: in|out|both")
	return cmd
}

// --- check -----------------------------------------------------------------

func (a *app) checkCmd() *cobra.Command {
	var contains bool
	var kind string
	cmd := &cobra.Command{
		Use:   "check <ip|cidr|host|domain|glob>",
		Short: "Search every backend for whether a target is blocked",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			k := model.KindBan
			if strings.EqualFold(kind, "allow") {
				k = model.KindAllow
			}
			entries, warns, err := a.mgr.Search(cmd.Context(), args[0], contains, k)
			if err != nil {
				return err
			}
			if !a.flagJSON && len(entries) == 0 {
				fmt.Fprintf(a.out, "%s: not found in any %s list\n", args[0], k)
			}
			return a.renderEntries(entries, warns)
		},
	}
	cmd.Flags().BoolVar(&contains, "contains", false, "also match covering/overlapping CIDRs")
	cmd.Flags().StringVar(&kind, "kind", "ban", "ban|allow")
	return cmd
}

// --- ban / unban / allow / unallow ----------------------------------------

func (a *app) banCmd() *cobra.Command {
	var via, duration, reason, scope string
	cmd := &cobra.Command{
		Use:   "ban <ip|cidr|host>",
		Short: "Ban an IP, CIDR, or hostname (resolved to addresses)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			dur, err := validate.Duration(duration)
			if err != nil {
				return err
			}
			targets, hostNote, err := a.expandTargets(cmd.Context(), args[0], scope)
			if err != nil {
				return err
			}
			var results []model.Result
			for _, t := range targets {
				req := model.ActionRequest{
					Value: t, Scope: model.Scope(scope), Backend: via,
					Duration: dur, Reason: joinReason(reason, hostNote), DryRun: a.flagDryRun,
				}
				res, berr := a.mgr.Ban(cmd.Context(), req, a.flagForce)
				if berr != nil {
					return berr
				}
				results = append(results, res)
			}
			return a.renderResults(results)
		},
	}
	cmd.Flags().StringVar(&via, "via", "", "target backend (default: auto)")
	cmd.Flags().StringVar(&duration, "duration", "", "ban duration, e.g. 4h (default: permanent)")
	cmd.Flags().StringVar(&reason, "reason", "", "reason recorded in the audit trail")
	cmd.Flags().StringVar(&scope, "scope", "", "ip|range|domain (default: inferred)")
	return cmd
}

func (a *app) unbanCmd() *cobra.Command {
	var via string
	var allBackends bool
	cmd := &cobra.Command{
		Use:   "unban <ip|cidr|host>",
		Short: "Remove a ban, routing to the owning backend",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			targets, _, err := a.expandTargets(cmd.Context(), args[0], "")
			if err != nil {
				return err
			}
			var results []model.Result
			for _, t := range targets {
				rs, uerr := a.mgr.Unban(cmd.Context(), t, via, allBackends, a.flagDryRun)
				results = append(results, rs...)
				if uerr != nil {
					return uerr
				}
			}
			return a.renderResults(results)
		},
	}
	cmd.Flags().StringVar(&via, "via", "", "target backend (default: every owner)")
	cmd.Flags().BoolVar(&allBackends, "all-backends", false, "also clear enforcement-layer copies")
	return cmd
}

func (a *app) allowCmd() *cobra.Command {
	var via, duration string
	cmd := &cobra.Command{
		Use:   "allow <ip|cidr|host>",
		Short: "Add an IP/CIDR/host to a backend allowlist",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			dur, err := validate.Duration(duration)
			if err != nil {
				return err
			}
			targets, _, err := a.expandTargets(cmd.Context(), args[0], "")
			if err != nil {
				return err
			}
			var results []model.Result
			for _, t := range targets {
				req := model.ActionRequest{Value: t, Scope: model.Scope(""), Backend: via, Duration: dur, DryRun: a.flagDryRun}
				res, aerr := a.mgr.Allow(cmd.Context(), req)
				if aerr != nil {
					return aerr
				}
				results = append(results, res)
			}
			return a.renderResults(results)
		},
	}
	cmd.Flags().StringVar(&via, "via", "", "target backend (default: auto)")
	cmd.Flags().StringVar(&duration, "duration", "", "allow duration, e.g. 7d→168h (default: permanent)")
	return cmd
}

func (a *app) unallowCmd() *cobra.Command {
	var via string
	cmd := &cobra.Command{
		Use:   "unallow <ip|cidr|host>",
		Short: "Remove an allowlist entry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			targets, _, err := a.expandTargets(cmd.Context(), args[0], "")
			if err != nil {
				return err
			}
			var results []model.Result
			for _, t := range targets {
				rs, uerr := a.mgr.Unallow(cmd.Context(), t, via, a.flagDryRun)
				results = append(results, rs...)
				if uerr != nil {
					return uerr
				}
			}
			return a.renderResults(results)
		},
	}
	cmd.Flags().StringVar(&via, "via", "", "target backend (default: every owner)")
	return cmd
}

func (a *app) undoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "undo",
		Short: "Roll back the most recent mutating action",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			res, err := a.mgr.Undo(cmd.Context(), a.flagDryRun)
			if err != nil {
				return err
			}
			return a.renderResults([]model.Result{res})
		},
	}
}

// --- helpers ---------------------------------------------------------------

// expandTargets validates the input and, for a hostname (when scope is not
// domain), resolves it to addresses. IP/CIDR/domain inputs pass through as-is.
func (a *app) expandTargets(ctx context.Context, value, scope string) ([]string, string, error) {
	if scope == "domain" {
		if err := validate.Domain(value); err != nil {
			return nil, "", err
		}
		return []string{value}, "", nil
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return []string{value}, "", nil
	}
	if _, err := netip.ParsePrefix(value); err == nil {
		return []string{value}, "", nil
	}
	// Treat as a hostname: resolve to addresses.
	if err := validate.Hostname(value); err != nil {
		return nil, "", err
	}
	addrs, err := a.mgr.Resolver().Hostname(ctx, value)
	if err != nil {
		return nil, "", fmt.Errorf("resolve %s: %w", value, err)
	}
	if len(addrs) == 0 {
		return nil, "", fmt.Errorf("%s did not resolve to any address", value)
	}
	out := make([]string, 0, len(addrs))
	for _, x := range addrs {
		out = append(out, x.String())
	}
	return out, "host: " + value, nil
}

func joinReason(reason, note string) string {
	switch {
	case reason == "":
		return note
	case note == "":
		return reason
	default:
		return reason + " (" + note + ")"
	}
}

func filterEntries(entries []model.Entry, origin, backend, direction string) []model.Entry {
	if origin == "" && backend == "" && direction == "" {
		return entries
	}
	dir := normalizeDirection(direction)
	out := entries[:0]
	for _, e := range entries {
		if origin != "" && !strings.EqualFold(string(e.Origin), origin) {
			continue
		}
		if backend != "" && !strings.EqualFold(e.Backend, backend) {
			continue
		}
		if dir != "" && e.Direction != dir {
			continue
		}
		out = append(out, e)
	}
	return out
}

func normalizeDirection(d string) model.Direction {
	switch strings.ToLower(d) {
	case "in", "inbound":
		return model.DirInbound
	case "out", "outbound":
		return model.DirOutbound
	case "both":
		return model.DirBoth
	default:
		return ""
	}
}

func (a *app) renderEntries(entries []model.Entry, warns []string) error {
	if a.flagJSON {
		enc := json.NewEncoder(a.out)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Entries  []model.Entry `json:"entries"`
			Warnings []string      `json:"warnings,omitempty"`
		}{entries, warns})
	}
	tw := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "VALUE\tFAMILY\tSCOPE\tKIND\tDIR\tORIGIN\tBACKEND\tDETAIL\tEXPIRES\tALSO-SEEN-IN")
	for _, e := range entries {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			e.Value, dash(string(e.Family)), dash(string(e.Scope)), string(e.Kind),
			dash(string(e.Direction)), string(e.Origin), e.Backend, dash(e.Detail),
			expiresStr(e), dash(strings.Join(e.AlsoSeenIn, ",")))
	}
	_ = tw.Flush()
	for _, w := range warns {
		fmt.Fprintf(a.out, "warning: %s\n", w)
	}
	return nil
}

func (a *app) renderResults(results []model.Result) error {
	if a.flagJSON {
		enc := json.NewEncoder(a.out)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Results []model.Result `json:"results"`
		}{results})
	}
	for _, r := range results {
		switch {
		case r.DryRun:
			fmt.Fprintf(a.out, "[dry-run] %s %s via %s:\n", r.Action, r.Value, r.Backend)
			for _, c := range r.Commands {
				fmt.Fprintf(a.out, "    %s\n", c)
			}
		case r.Changed:
			fmt.Fprintf(a.out, "%s %s via %s: done\n", r.Action, r.Value, r.Backend)
		default:
			msg := r.Message
			if msg == "" {
				msg = "no change"
			}
			fmt.Fprintf(a.out, "%s %s via %s: %s\n", r.Action, r.Value, r.Backend, msg)
		}
	}
	return nil
}

func expiresStr(e model.Entry) string {
	if e.ExpiresAt == nil {
		return "permanent"
	}
	return e.ExpiresAt.Format("2006-01-02 15:04")
}
