package cli

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/stympy/breakwater-cli/internal/bundle"
	"github.com/stympy/breakwater-cli/internal/term"
)

// newBundleCommand is the parent of the bundle subcommands.
func newBundleCommand(g *globals) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Create, verify and load offline bundles",
	}
	cmd.AddCommand(newBundleCreateCommand(g))
	cmd.AddCommand(newBundleVerifyCommand(g))
	cmd.AddCommand(newBundleLoadCommand(g))
	return cmd
}

func newBundleVerifyCommand(g *globals) *cobra.Command {
	return &cobra.Command{
		Use:   "verify <file>",
		Short: "Check a bundle's structure and every digest in it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			if _, err := os.Stat(path); err != nil {
				return err
			}
			b, err := bundle.Open(path)
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			defer b.Close()
			printBundleSummary(g, b)
			return nil
		},
	}
}

func printBundleSummary(g *globals, b *bundle.Bundle) {
	h, m := b.Header(), b.Manifest()
	out := g.io.Out
	platforms := "all"
	if h.Platforms != nil {
		platforms = clean(strings.Join(h.Platforms, ", "))
	}
	fmt.Fprintf(out, "Vendor:       %s (%s)\n", clean(m.Vendor.Name), clean(m.Vendor.Slug))
	fmt.Fprintf(out, "Product:      %s (%s)\n", clean(m.Product.Name), clean(m.Product.Slug))
	fmt.Fprintf(out, "Version:      %s\n", clean(m.Version))
	fmt.Fprintf(out, "Created:      %s\n", clean(h.CreatedAt))
	fmt.Fprintf(out, "CLI version:  %s\n", clean(h.CLIVersion))
	fmt.Fprintf(out, "Platforms:    %s\n", platforms)

	fmt.Fprintf(out, "\nImages (%d):\n", len(b.Images()))
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, img := range b.Images() {
		noun := "platforms"
		if img.Platforms == 1 {
			noun = "platform"
		}
		fmt.Fprintf(tw, "  %s@%s\t%d %s\t%s\n", clean(img.Reference), clean(shortDigest(img.Digest)), img.Platforms, noun, humanSize(img.Size))
	}
	tw.Flush()

	fmt.Fprintf(out, "\nFiles (%d):\n", len(h.Files))
	tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, f := range h.Files {
		fmt.Fprintf(tw, "  %s\t%s\n", clean(f.Name), humanSize(f.Size))
	}
	tw.Flush()

	fmt.Fprintf(out, "\nBinaries (%d):\n", len(h.Bin))
	tw = tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, x := range h.Bin {
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", clean(x.Name), clean(x.Platform), humanSize(x.Size))
	}
	tw.Flush()

	fmt.Fprintln(out, "\nOK: every image, file and binary matches its digest.")
}

// clean drops control and format characters (escape sequences, bidi
// overrides) from bundle-supplied text before it reaches a terminal.
func clean(s string) string { return term.Clean(s) }

// shortDigest is "sha256:" and the first 12 hex characters.
func shortDigest(d string) string {
	algo, hex, ok := strings.Cut(d, ":")
	if !ok || len(hex) <= 12 {
		return d
	}
	return algo + ":" + hex[:12]
}

// humanSize is a byte count in binary units: "512 B", "1.5 KiB", "2.0 GiB".
func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}
