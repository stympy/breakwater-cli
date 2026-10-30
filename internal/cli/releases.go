package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/stympy/breakwater-cli/internal/api"
)

func newReleasesCommand(g *globals) *cobra.Command {
	var product string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "releases",
		Short: "List the releases this token can see",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			origin, err := g.APIOrigin()
			if err != nil {
				return err
			}
			creds, err := g.Credentials(cmd)
			if err != nil {
				return err
			}
			releases, rawData, err := api.New(origin, creds).ReleasesRaw(cmd.Context(), product)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if asJSON {
				var buf bytes.Buffer
				if err := json.Indent(&buf, rawData, "", "  "); err != nil {
					return err
				}
				_, err := fmt.Fprintln(out, buf.String())
				return err
			}
			if len(releases) == 0 {
				_, err := fmt.Fprintln(out, "No releases available to this token.")
				return err
			}
			tw := tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
			fmt.Fprintln(tw, "PRODUCT\tVERSION\tPUBLISHED")
			for _, r := range releases {
				fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Product.Slug, r.Version, publishedDate(r.PublishedAt))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&product, "product", "", "only releases of this product (slug)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

func publishedDate(s string) string {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC().Format("2006-01-02")
	}
	return s
}
