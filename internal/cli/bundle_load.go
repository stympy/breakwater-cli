package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	platform   string
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
<registry>/docker.io/library/postgres:16.4 (a port in that host becomes
"_": <registry>/localhost_5000/tool:1). --username and --password-stdin
give the registry's credentials; without them, Docker's credential store is
used, or none.

With --docker, each image is loaded for Docker's platform, or for
--platform os/arch[/variant]. --username and --password-stdin don't apply.

--rewrite-files <dir> writes the release's compose and YAML files to <dir>
with their image: lines pointing at the loaded or pushed images. Files that
pin images by @sha256: digest need it with --docker, since docker load
doesn't record registry digests.

--ca-file adds trusted CA certificates for the --registry host.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.docker == cmd.Flags().Changed("registry") {
				fmt.Fprintln(g.io.Err, cmd.UsageString())
				return errors.New("use exactly one of --docker and --registry")
			}
			if o.insecure && o.docker {
				return errors.New("--insecure only applies to --registry")
			}
			if o.platform != "" && !o.docker {
				return errors.New("--platform only applies to --docker")
			}
			if o.docker && (g.username != "" || g.passwordStdin) {
				return errors.New("--username and --password-stdin only apply to --registry; loading into Docker needs no credentials")
			}
			return runBundleLoad(cmd, g, args[0], o)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&o.docker, "docker", false, "load the images into the local Docker")
	f.StringVar(&o.registry, "registry", "", "push the images to this registry (host[/prefix])")
	f.StringVar(&o.rewriteDir, "rewrite-files", "", "write the release's compose and YAML files, pointing at the loaded images, to this directory")
	f.BoolVar(&o.insecure, "insecure", false, "allow plain HTTP to the --registry host")
	f.StringVar(&o.platform, "platform", "", "with --docker, load images for this platform (os/arch[/variant]) instead of Docker's")
	f.StringVar(&o.dockerCmd, "docker-command", "docker", "the docker command (testing)")
	_ = f.MarkHidden("docker-command")
	return cmd
}

func runBundleLoad(cmd *cobra.Command, g *globals, path string, o loadOptions) error {
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	stderr, stdout := g.io.Err, g.io.Out

	// Check the target before the (slow) verification.
	var auth authn.Authenticator
	var tr *http.Transport
	if o.docker && o.platform != "" && !bundle.ValidPlatform(o.platform) {
		return fmt.Errorf("invalid platform %q: use os/arch or os/arch/variant, like linux/amd64 or linux/arm/v7", o.platform)
	}
	if !o.docker {
		if err := load.CheckRegistry(o.registry); err != nil {
			return err
		}
		var err error
		if tr, err = g.Transport(); err != nil {
			return err
		}
		if auth, err = registryAuth(cmd, g, o.registry); err != nil {
			return err
		}
	}
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
		mappings, skipped, err = load.ToDocker(ctx, b, o.dockerCmd, o.platform, stdout)
		if err != nil {
			return err
		}
		if len(mappings) == 0 {
			fmt.Fprintf(stderr, "warning: nothing was loaded; Docker can't run any of the bundle's %s (push them to a registry with --registry instead)\n", plural(len(skipped), "image"))
		}
		if o.rewriteDir == "" && pinsDigests(b) {
			fmt.Fprintln(stderr, "note: the bundle's files pin images by @sha256: digest, which docker load doesn't record; pass --rewrite-files <dir> for copies that use the loaded names")
		}
	} else {
		fmt.Fprintf(stderr, "Pushing the images to %s\n", o.registry)
		mappings, err = load.ToRegistry(ctx, b, o.registry, auth, o.insecure, tr, stdout)
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

// pinsDigests reports whether any of the bundle's files mentions
// "@sha256:", as an image reference pinned by digest does.
func pinsDigests(b *bundle.Bundle) bool {
	for _, f := range b.Header().Files {
		rc, err := b.File(f.Name)
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(rc, 4<<20))
		rc.Close()
		if bytes.Contains(data, []byte("@sha256:")) {
			return true
		}
	}
	return false
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
