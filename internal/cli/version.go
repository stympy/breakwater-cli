package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/stympy/breakwater-cli/internal/version"
)

func newVersionCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the breakwater version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(g.io.Out, "breakwater %s (%s/%s)\n", version.Version, runtime.GOOS, runtime.GOARCH)
			return nil
		},
	}
}
