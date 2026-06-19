// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package cli

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/extremeshok/omniban/internal/manager"
)

func (a *app) statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show detected backends and their state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			statuses := a.mgr.Detect(cmd.Context())
			if a.flagJSON {
				return a.printStatusJSON(statuses)
			}
			a.printStatusTable(statuses)
			a.maybeNotifyUpdate(cmd.Context())
			return nil
		},
	}
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (a *app) printStatusTable(statuses []manager.Status) {
	tw := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "BACKEND\tLAYER\tINSTALLED\tACTIVE\tENFORCING\tVERSION")
	for _, s := range statuses {
		if !s.Detection.Installed {
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			s.Name, s.Layer,
			yesno(s.Detection.Installed),
			yesno(s.Detection.Active),
			yesno(s.Detection.Enforcing),
			dash(s.Detection.Version),
		)
	}
	_ = tw.Flush()

	// Per-backend and host-level warnings.
	for _, s := range statuses {
		if !s.Detection.Installed {
			continue
		}
		for _, w := range s.Detection.Warnings {
			fmt.Fprintf(a.out, "warning [%s]: %s\n", s.Name, w)
		}
	}
	for _, w := range a.mgr.CrossWarnings(statuses) {
		fmt.Fprintf(a.out, "warning: %s\n", w)
	}
}

func (a *app) printStatusJSON(statuses []manager.Status) error {
	payload := struct {
		Backends     []manager.Status `json:"backends"`
		ManualTarget string           `json:"manual_ban_target"`
		Warnings     []string         `json:"warnings"`
	}{
		Backends:     statuses,
		ManualTarget: a.mgr.ManualTarget(statuses),
		Warnings:     a.mgr.CrossWarnings(statuses),
	}
	enc := json.NewEncoder(a.out)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}
