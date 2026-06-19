// omniban — one ban manager for every Linux firewall & IDS.
//
// Coded by Adrian Jon Kriel :: admin@extremeshok.com
// Licensed under the BSD 3-Clause License.

package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

func (a *app) versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "version",
		Short:             "Print the omniban version",
		Args:              cobra.NoArgs,
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil }, // skip config load
		RunE: func(*cobra.Command, []string) error {
			fmt.Fprintf(a.out, "omniban %s (%s/%s, %s)\n",
				a.version, runtime.GOOS, runtime.GOARCH, runtime.Version())
			return nil
		},
	}
}
