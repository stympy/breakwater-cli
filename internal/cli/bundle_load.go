package cli

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/spf13/cobra"
	"github.com/stympy/breakwater-cli/internal/bundle"
	"github.com/stympy/breakwater-cli/internal/load"
)

type loadOptions struct {
	docker     bool
	registry   string
	rewriteDir string
	insecure   bool
	dockerCmd  string
}

func newBundleLoadCommand(g *globals) *cobra.Command {
	var o loadOptions
	cmd := &cobra.Command{
		Use:   "load <file> (--docker | --registry host[/prefix])",
		Short: "Verify a bundle, then load its images into Docker or push them to a registry",
		Long: `Verify a bundle, then load its images into Docker (--docker) or push them to
your own registry (--registry host[/prefix]).

With --registry, internal images go to <registry>/<repository>:<tag> and
external ones to <registry>/<original registry>/<repository>:<tag>, such as
<registry>/docker.io/library/postgres:16.4. --username and --password-stdin
give the registry's credentials; without them, Docker's credential store is
used, or none.

--rewrite-files <dir> writes the release's compose and YAML files to <dir>
with their image: lines pointing at the loaded or pushed images.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.docker == cmd.Flags().Changed("registry") {
				fmt.Fprintln(g.io.Err, cmd.UsageString())
				return errors.New("use exactly one of --docker and --registry")
			}
			if o.insecure && o.docker {
				return errors.New("--insecure only applies to --registry")
			}
			return runBundleLoad(cmd, g, args[0], o)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&o.docker, "docker", false, "load the images into the local Docker")
	f.StringVar(&o.registry, "registry", "", "push the images to this registry (host[/prefix])")
	f.StringVar(&o.rewriteDir, "rewrite-files", "", "write the release's compose and YAML files, pointing at the loaded images, to this directory")
	f.BoolVar(&o.insecure, "insecure", false, "allow plain HTTP to the --registry host")
	f.StringVar(&o.dockerCmd, "docker-command", "docker", "the docker command (testing)")
	_ = f.MarkHidden("docker-command")
	return cmd
}

func runBundleLoad(cmd *cobra.Command, g *globals, path string, o loadOptions) error {
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	stderr, stdout := g.io.Err, g.io.Out

	if _, err := os.Stat(path); err != nil {
		return err
	}
	fmt.Fprintf(stderr, "Verifying %s\n", path)
	b, err := bundle.Open(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer b.Close()
	if o.rewriteDir != "" {
		if err := load.CheckRewrite(b, o.rewriteDir); err != nil {
			return err
		}
	}

	var mappings []load.Mapping
	if o.docker {
		fmt.Fprintln(stderr, "Loading the images into Docker")
		var skipped []load.Skipped
		mappings, skipped, err = load.ToDocker(ctx, b, o.dockerCmd, stdout)
		if err != nil {
			return err
		}
		if len(mappings) == 0 {
			fmt.Fprintf(stderr, "warning: nothing was loaded; Docker can't run any of the bundle's %s (push them to a registry with --registry instead)\n", plural(len(skipped), "image"))
		}
	} else {
		auth, err := registryAuth(cmd, g, o.registry)
		if err != nil {
			return err
		}
		fmt.Fprintf(stderr, "Pushing the images to %s\n", o.registry)
		mappings, err = load.ToRegistry(ctx, b, o.registry, auth, o.insecure, stdout)
		if err != nil {
			return err
		}
	}

	if o.rewriteDir != "" {
		written, err := load.RewriteFiles(b, o.rewriteDir, mappings, !o.docker)
		if err != nil {
			return err
		}
		for _, p := range written {
			fmt.Fprintf(stdout, "Wrote %s\n", clean(p))
		}
		if len(written) == 0 {
			fmt.Fprintln(stderr, "The bundle has no compose or YAML files with image: lines to rewrite.")
		}
	}
	return nil
}

// registryAuth is the target registry's credentials: --username with
// --password-stdin when given, else the Docker credential store for the
// registry's host (anonymous if it has nothing). BREAKWATER_USERNAME and
// BREAKWATER_TOKEN are Breakwater's credentials, not the target's, so
// they're not used.
func registryAuth(cmd *cobra.Command, g *globals, registry string) (authn.Authenticator, error) {
	if g.username != "" || g.passwordStdin {
		creds, err := g.Credentials(cmd)
		if err != nil {
			return nil, err
		}
		return authn.FromConfig(authn.AuthConfig{Username: creds.Username, Password: creds.Password}), nil
	}
	host, _, _ := strings.Cut(registry, "/")
	reg, err := name.NewRegistry(host)
	if err != nil {
		return nil, fmt.Errorf("--registry %q: invalid host %q", registry, host)
	}
	auth, err := authn.DefaultKeychain.Resolve(reg)
	if err != nil {
		return nil, fmt.Errorf("reading the Docker credential store: %w", err)
	}
	return auth, nil
}
