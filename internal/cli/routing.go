// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/extremeshok/omniban/internal/model"
	"github.com/extremeshok/omniban/internal/validate"
)

func (a *app) sinkholeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sinkhole <domain>",
		Short: "Null-route a domain via /etc/hosts (outbound)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			if err := validate.Domain(args[0]); err != nil {
				return err
			}
			res, err := a.mgr.Ban(cmd.Context(), model.ActionRequest{
				Value: args[0], Scope: model.ScopeDomain, Backend: "hosts", DryRun: a.flagDryRun,
			}, a.flagForce)
			if err != nil {
				return err
			}
			return a.renderResults([]model.Result{res})
		},
	}
}

func (a *app) nullRouteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "null-route <ip|cidr>",
		Short: "Drop all traffic to an IP/CIDR via a blackhole route (both directions)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			if _, _, err := validate.IPOrCIDR(args[0]); err != nil {
				return err
			}
			res, err := a.mgr.Ban(cmd.Context(), model.ActionRequest{
				Value: args[0], Backend: "blackhole", DryRun: a.flagDryRun,
			}, a.flagForce)
			if err != nil {
				return err
			}
			return a.renderResults([]model.Result{res})
		},
	}
}

func (a *app) applyRoutesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "apply-routes",
		Short: "Replay persisted blackhole routes (run at boot by the systemd unit)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			if err := a.mgr.ApplyPersisted(cmd.Context()); err != nil {
				return err
			}
			fmt.Fprintln(a.out, "persisted routes applied")
			return nil
		},
	}
}
