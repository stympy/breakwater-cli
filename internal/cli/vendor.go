package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stympy/breakwater-cli/internal/api"
	"github.com/stympy/breakwater-cli/internal/term"
)

const apiTokenEnv = "BREAKWATER_API_TOKEN"

func newVendorCommand(g *globals) *cobra.Command {
	vendor := &cobra.Command{
		Use:   "vendor",
		Short: "Manage your products as a vendor (needs a vapi_ API token)",
	}
	releases := &cobra.Command{Use: "releases", Short: "Manage releases"}
	releases.AddCommand(newVendorReleasesCreateCommand(g))
	vendor.AddCommand(releases)
	return vendor
}

func newVendorReleasesCreateCommand(g *globals) *cobra.Command {
	var (
		token, notes, notesFile string
		images, externals       []string
		files                   []string
		asJSON                  bool
	)
	cmd := &cobra.Command{
		Use:   "create <product id> <version>",
		Short: "Create and publish a release",
		Long: `Create and publish a release of a product (given by its id, as in the vendor API).

The API token (a vapi_ token with the write scope) comes from --token or the
BREAKWATER_API_TOKEN environment variable. The customer credentials the other
commands use are never sent.`,
		Example: `  breakwater vendor releases create prod_abc 2.4.1 \
    --notes-file CHANGELOG.md \
    --image api:2.4.1 --external-image postgres:16.4 \
    --file compose.yaml --file ./dist/install.sh=install.sh`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			product, ver := args[0], args[1]
			if notes != "" && notesFile != "" {
				return errors.New("give --notes or --notes-file, not both")
			}
			if token == "" {
				token = g.io.Getenv(apiTokenEnv)
			}
			token = strings.TrimSpace(token)
			if token == "" {
				return fmt.Errorf("no API token: set %s or pass --token (a vapi_ token with the write scope)", apiTokenEnv)
			}
			if !strings.HasPrefix(token, "vapi_") {
				return errors.New("the API token must be a vapi_ token (registry tokens don't work on the vendor API)")
			}
			origin, err := g.APIOrigin()
			if err != nil {
				return err
			}
			rel := api.NewRelease{Version: ver, Notes: notes}
			if notesFile != "" {
				b, err := readNotes(cmd.InOrStdin(), notesFile)
				if err != nil {
					return err
				}
				rel.Notes = string(b)
			}
			fileSpecs, err := readFiles(files)
			if err != nil {
				return err
			}
			rel.Files = fileSpecs

			tr, err := g.Transport()
			if err != nil {
				return err
			}
			client := api.NewVendor(origin, token, api.WithHTTPClient(&http.Client{Transport: tr}))
			if len(images) > 0 {
				repos, err := client.Repositories(cmd.Context())
				if err != nil {
					return err
				}
				for _, spec := range images {
					img, err := resolveImage(spec, repos)
					if err != nil {
						return err
					}
					rel.Images = append(rel.Images, img)
				}
			}
			for _, ref := range externals {
				if strings.TrimSpace(ref) == "" {
					return errors.New("--external-image needs an image reference")
				}
				rel.Images = append(rel.Images, api.ReleaseImage{External: ref})
			}

			created, err := client.CreateRelease(cmd.Context(), product, rel)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			releaseURL := origin.String() + "/vendor/products/" + url.PathEscape(product) + "/releases/" + url.PathEscape(created.Version)
			if asJSON {
				var data map[string]any
				if err := json.Unmarshal(created.Raw, &data); err != nil {
					return err
				}
				data["url"] = releaseURL
				var buf bytes.Buffer
				enc := json.NewEncoder(&buf)
				enc.SetIndent("", "  ")
				if err := enc.Encode(data); err != nil {
					return err
				}
				_, err := out.Write(buf.Bytes())
				return err
			}
			fmt.Fprintf(out, "Published %s %s (%d images, %d files)\n", term.Clean(product), term.Clean(created.Version), len(created.Images), len(created.Files))
			fmt.Fprintln(out, releaseURL)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&token, "token", "", "vapi_ API token with the write scope (default: $"+apiTokenEnv+"; prefer the variable, as flags show in process lists)")
	f.StringVar(&notes, "notes", "", "release notes (Markdown)")
	f.StringVar(&notesFile, "notes-file", "", "read release notes from this file (- for stdin)")
	f.StringArrayVar(&images, "image", nil, "a repository image, <repository id or name>:<tag> (repeatable)")
	f.StringArrayVar(&externals, "external-image", nil, "an external image reference, e.g. postgres:16.4 (repeatable)")
	f.StringArrayVar(&files, "file", nil, "a file to attach, <path>[=<name in the release>] (repeatable; a path containing = that does not exist needs an explicit =<name>)")
	f.BoolVar(&asJSON, "json", false, "print the created release as JSON, with its URL as \"url\"")
	return cmd
}

func readNotes(stdin io.Reader, path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(stdin)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading --notes-file: %w", err)
	}
	return b, nil
}

func readFiles(specs []string) ([]api.ReleaseFile, error) {
	var out []api.ReleaseFile
	for _, spec := range specs {
		path, name := spec, ""
		// A spec that is itself an existing file is a bare path, even when it
		// contains "="; otherwise the last "=" starts the release file name.
		if _, statErr := os.Stat(spec); statErr == nil {
			// bare path
		} else if i := strings.LastIndex(spec, "="); i >= 0 {
			path, name = spec[:i], spec[i+1:]
			if name == "" {
				return nil, fmt.Errorf("--file %q: the name after = is empty", spec)
			}
		}
		if path == "" {
			return nil, fmt.Errorf("--file %q: no path", spec)
		}
		if name == "" {
			name = filepath.Base(path)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading --file: %w", err)
		}
		out = append(out, api.ReleaseFile{Name: name, ContentBase64: base64.StdEncoding.EncodeToString(b)})
	}
	return out, nil
}

// resolveImage turns "<repository id or name>:<tag>" into an API image. An
// id wins over a name; a name that matches several repositories is an error.
func resolveImage(spec string, repos []api.Repository) (api.ReleaseImage, error) {
	i := strings.LastIndex(spec, ":")
	if i <= 0 || i == len(spec)-1 {
		return api.ReleaseImage{}, fmt.Errorf("--image %q: use <repository id or name>:<tag>", spec)
	}
	repo, tag := spec[:i], spec[i+1:]
	for _, r := range repos {
		if r.ID == repo {
			return api.ReleaseImage{RepositoryID: r.ID, Tag: tag}, nil
		}
	}
	var match []api.Repository
	for _, r := range repos {
		if r.Name == repo || r.FullPath == repo {
			match = append(match, r)
		}
	}
	switch len(match) {
	case 0:
		return api.ReleaseImage{}, fmt.Errorf("--image %q: no repository with id or name %q", spec, term.Clean(repo))
	case 1:
		return api.ReleaseImage{RepositoryID: match[0].ID, Tag: tag}, nil
	}
	return api.ReleaseImage{}, fmt.Errorf("--image %q: several repositories are named %q; use the repository id", spec, term.Clean(repo))
}
