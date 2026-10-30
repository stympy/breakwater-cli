// Package cli is the cobra command layer of the breakwater CLI.
package cli

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"unicode"

	"github.com/spf13/cobra"
	"github.com/stympy/breakwater-cli/internal/api"
	"github.com/stympy/breakwater-cli/internal/credentials"
	"github.com/stympy/breakwater-cli/internal/transport"
)

const (
	defaultHost         = "https://app.breakwaterapp.com"
	defaultRegistryHost = "registry.breakwaterapp.com"
)

// IOStreams are the process streams and environment a command runs with.
// Tests inject their own.
type IOStreams struct {
	In     io.Reader
	Out    io.Writer
	Err    io.Writer
	Getenv func(string) string
}

// DefaultIOStreams uses the real process streams and environment.
func DefaultIOStreams() *IOStreams {
	return &IOStreams{In: os.Stdin, Out: os.Stdout, Err: os.Stderr, Getenv: os.Getenv}
}

// globals holds the persistent root flags, shared with subcommands.
type globals struct {
	io            *IOStreams
	host          string
	registryHost  string
	username      string
	passwordStdin bool
	caFile        string
}

// Transport is the HTTP transport for every request: ggcr's defaults with a
// response-header timeout, trusting --ca-file's certificates as well as
// the system's.
func (g *globals) Transport() (*http.Transport, error) {
	roots, err := transport.LoadCAFile(g.caFile)
	if err != nil {
		return nil, err
	}
	return transport.New(roots), nil
}

// APIClient is a customer API client for --host with creds.
func (g *globals) APIClient(origin *url.URL, creds credentials.Credentials) (*api.Client, error) {
	tr, err := g.Transport()
	if err != nil {
		return nil, err
	}
	return api.New(origin, creds, api.WithHTTPClient(&http.Client{Transport: tr})), nil
}

// Credentials resolves credentials per the documented order.
func (g *globals) Credentials(cmd *cobra.Command) (credentials.Credentials, error) {
	return credentials.Resolve(credentials.Options{
		Username:      g.username,
		PasswordStdin: g.passwordStdin,
		Stdin:         cmd.InOrStdin(),
		Getenv:        g.io.Getenv,
		RegistryHost:  g.registryHost,
	})
}

// APIOrigin validates --host: http(s), a host, and no path beyond "/".
func (g *globals) APIOrigin() (*url.URL, error) {
	u, err := url.Parse(g.host)
	if err != nil {
		return nil, fmt.Errorf("invalid --host %q: %w", g.host, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid --host %q: must be an http(s) URL with a host", g.host)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("invalid --host %q: must be an origin without a path, credentials or query", g.host)
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

// newRootCommand builds the command tree. Each subcommand file adds itself here.
func newRootCommand(ios *IOStreams) *cobra.Command {
	own := *ios // don't mutate the caller's streams
	ios = &own
	if ios.Getenv == nil {
		ios.Getenv = os.Getenv
	}
	g := &globals{io: ios}
	root := &cobra.Command{
		Use:           "breakwater",
		Short:         "Fetch and load licensed Breakwater releases, including air-gapped bundles",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetIn(ios.In)
	root.SetOut(ios.Out)
	root.SetErr(ios.Err)
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		// Flag errors keep the usage text; runtime errors don't.
		fmt.Fprintln(ios.Err, cmd.UsageString())
		return err
	})

	f := root.PersistentFlags()
	f.StringVar(&g.host, "host", defaultHost, "Breakwater API origin")
	f.StringVar(&g.registryHost, "registry-host", defaultRegistryHost, "Breakwater registry host")
	f.StringVar(&g.username, "username", "", "username (use with --password-stdin)")
	f.BoolVar(&g.passwordStdin, "password-stdin", false, "read the password (a pull token) from stdin")
	f.StringVar(&g.caFile, "ca-file", "", "also trust the CA certificates in this PEM file (for a TLS-inspecting proxy or a private registry)")

	root.AddCommand(newVersionCommand(g))
	root.AddCommand(newReleasesCommand(g))
	root.AddCommand(newBundleCommand(g))
	return root
}

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	return execute(DefaultIOStreams(), os.Args[1:])
}

func execute(ios *IOStreams, args []string) int {
	root := newRootCommand(ios)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		fmt.Fprintf(ios.Err, "breakwater: %s\n", cleanMessage(strings.TrimSpace(err.Error())))
		return 1
	}
	return 0
}

// cleanMessage drops control and format characters other than newline and
// tab from an error message, since errors can quote hostile input.
func cleanMessage(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}
