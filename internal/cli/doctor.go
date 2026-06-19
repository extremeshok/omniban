// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the MIT License.

package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/extremeshok/omniban/internal/manager"
	"github.com/extremeshok/omniban/internal/model"
)

func (a *app) doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Run a health check across all backends and report warnings",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			statuses := a.mgr.Detect(cmd.Context())
			a.printDoctor(statuses)
			return nil
		},
	}
}

func (a *app) printDoctor(statuses []manager.Status) {
	var installed, activeIDS, activeFW int
	for _, s := range statuses {
		if !s.Detection.Installed {
			continue
		}
		installed++
		if s.Detection.Active {
			switch s.Layer {
			case model.LayerIDS:
				activeIDS++
			case model.LayerFirewall:
				activeFW++
			}
		}
	}

	fmt.Fprintf(a.out, "omniban %s — health report\n\n", a.version)
	fmt.Fprintf(a.out, "Detected backends: %d installed (%d active IDS, %d active firewall)\n",
		installed, activeIDS, activeFW)
	fmt.Fprintf(a.out, "Manual inbound-ban target: %s\n\n", dash(a.mgr.ManualTarget(statuses)))

	var warnings []string
	for _, s := range statuses {
		if !s.Detection.Installed {
			continue
		}
		for _, w := range s.Detection.Warnings {
			warnings = append(warnings, fmt.Sprintf("[%s] %s", s.Name, w))
		}
	}
	warnings = append(warnings, a.mgr.CrossWarnings(statuses)...)

	if len(warnings) == 0 {
		fmt.Fprintln(a.out, "No warnings. All detected backends look healthy.")
		return
	}
	fmt.Fprintf(a.out, "%d warning(s):\n", len(warnings))
	for _, w := range warnings {
		fmt.Fprintf(a.out, "  - %s\n", w)
	}
}
