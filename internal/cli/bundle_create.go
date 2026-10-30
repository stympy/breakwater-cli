package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/spf13/cobra"
	"github.com/stympy/breakwater-cli/internal/api"
	"github.com/stympy/breakwater-cli/internal/bundle"
	"github.com/stympy/breakwater-cli/internal/images"
	"github.com/stympy/breakwater-cli/internal/selfdist"
	"github.com/stympy/breakwater-cli/internal/version"
)

const (
	// maxEventPlatforms is the most platforms a bundle event takes.
	maxEventPlatforms = 16
	// maxFileSize and maxFilesTotal cap release files, which are held in
	// memory while the bundle is written.
	maxFileSize   = 1 << 20
	maxFilesTotal = 5 << 20
)

type createOptions struct {
	product, version string
	platforms        []string // nil: all
	out              string
	cliBinaries      []string
	force            bool
	insecure         []string
}

func newBundleCreateCommand(g *globals) *cobra.Command {
	var o createOptions
	cmd := &cobra.Command{
		Use:   "create <product> <version>",
		Short: "Pull a release's images and files into one offline bundle",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			o.product, o.version = args[0], args[1]
			if !cmd.Flags().Changed("platform") {
				o.platforms = nil
			} else if len(o.platforms) == 0 {
				return errors.New("--platform needs at least one platform, like linux/amd64")
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return runBundleCreate(ctx, cmd, g, o)
		},
	}
	f := cmd.Flags()
	f.StringSliceVar(&o.platforms, "platform", nil, "keep only these platforms of multi-platform images (os/arch[/variant], comma-separated)")
	f.StringVarP(&o.out, "output", "o", "", "bundle file to write (default <product>-<version>.bwbundle.tar)")
	f.StringSliceVar(&o.cliBinaries, "cli-binaries", nil, "also carry breakwater binaries for these platforms, downloaded from GitHub (e.g. linux/amd64,windows/amd64)")
	f.BoolVar(&o.force, "force", false, "overwrite the output file if it exists")
	f.StringSliceVar(&o.insecure, "insecure-registries", nil, "registry hosts that may be reached over plain HTTP (testing)")
	_ = f.MarkHidden("insecure-registries")
	return cmd
}

func defaultBundleName(product, version string) string {
	return product + "-" + version + ".bwbundle.tar"
}

// cleanPlatforms checks --platform values and drops repeats.
func cleanPlatforms(ps []string) ([]string, error) {
	if ps == nil {
		return nil, nil
	}
	var out []string
	for _, p := range ps {
		p = strings.TrimSpace(p)
		if !bundle.ValidPlatform(p) {
			return nil, fmt.Errorf("invalid platform %q: use os/arch or os/arch/variant, like linux/amd64 or linux/arm/v7", p)
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

// eventPlatforms are the platforms recorded with the bundle event: the
// requested ones, or else the sorted union of the images' platforms; at
// most 16, and "unknown/unknown" when there are none.
func eventPlatforms(requested []string, resolved [][]string) []string {
	var out []string
	if requested != nil {
		out = slices.Clone(requested)
	} else {
		for _, ps := range resolved {
			for _, p := range ps {
				if bundle.ValidPlatform(p) && !slices.Contains(out, p) {
					out = append(out, p)
				}
			}
		}
		slices.Sort(out)
	}
	if len(out) > maxEventPlatforms {
		out = out[:maxEventPlatforms]
	}
	if len(out) == 0 {
		out = []string{"unknown/unknown"}
	}
	return out
}

func warnEvent(g *globals, err error) {
	fmt.Fprintf(g.io.Err, "warning: couldn't record the bundle with Breakwater: %s\n", cleanMessage(err.Error()))
}

func runBundleCreate(ctx context.Context, cmd *cobra.Command, g *globals, o createOptions) error {
	stderr := g.io.Err
	platforms, err := cleanPlatforms(o.platforms)
	if err != nil {
		return err
	}
	for i, p := range o.cliBinaries {
		o.cliBinaries[i] = strings.TrimSpace(p)
	}
	if len(o.cliBinaries) > 0 {
		if err := selfdist.Check(version.Version, o.cliBinaries); err != nil {
			return err
		}
	}
	out := o.out
	if out == "" {
		out = defaultBundleName(o.product, o.version)
	}
	if !o.force {
		if err := refuseExisting(out); err != nil {
			return err
		}
	}

	// 1-2. Credentials and the manifest.
	origin, err := g.APIOrigin()
	if err != nil {
		return err
	}
	creds, err := g.Credentials(cmd)
	if err != nil {
		return err
	}
	client := api.New(origin, creds)
	m, rawManifest, err := client.Manifest(ctx, o.product, o.version)
	if err != nil {
		return err
	}
	if err := checkFileSizes(m.Files); err != nil {
		return err
	}

	// 3. Resolve every image.
	col := &images.Collector{
		RegistryHost:       g.registryHost,
		Auth:               authn.FromConfig(authn.AuthConfig{Username: creds.Username, Password: creds.Password}),
		UserAgent:          version.UserAgent(),
		InsecureRegistries: o.insecure,
	}
	var resolved []*images.Resolved
	var resolvedPlatforms [][]string
	for _, img := range m.Images {
		fmt.Fprintf(stderr, "Resolving %s\n", clean(img.Reference))
		r, err := col.Resolve(ctx, img, platforms)
		if err != nil {
			return err
		}
		resolved = append(resolved, r)
		resolvedPlatforms = append(resolvedPlatforms, r.Platforms)
	}

	// 4-5. Record the bundle event; it never fails the bundle.
	eventID, err := client.StartBundle(ctx, o.product, o.version, eventPlatforms(platforms, resolvedPlatforms))
	if err != nil {
		warnEvent(g, err)
	}

	// 6. Files, into memory (they're small).
	files := make([][]byte, len(m.Files))
	for i, f := range m.Files {
		fmt.Fprintf(stderr, "Downloading %s\n", clean(f.Name))
		var buf bytes.Buffer
		if err := client.DownloadFile(ctx, f, &buf); err != nil {
			return err
		}
		files[i] = buf.Bytes()
	}

	// 7. Binaries: the running one, and any asked for.
	running, err := selfdist.Running()
	if err != nil {
		return err
	}
	bins := []selfdist.Binary{running}
	if others := selfdist.Others(o.cliBinaries); len(others) > 0 {
		fmt.Fprintf(stderr, "Downloading breakwater %s for %s\n", version.Version, strings.Join(others, ", "))
		downloaded, err := selfdist.Download(ctx, version.Version, o.cliBinaries, &http.Client{}, "")
		if err != nil {
			return err
		}
		defer selfdist.Remove(downloaded)
		bins = append(bins, downloaded...)
	}

	// 8-10. Write the bundle.
	plan, err := planBundle(m, rawManifest, platforms, resolved, files, bins)
	if err != nil {
		return err
	}
	if err := writeBundle(ctx, g, col, plan, out, o.force); err != nil {
		return err
	}
	st, err := os.Stat(out)
	if err != nil {
		return err
	}

	// 11. Complete the event.
	if eventID != "" {
		if err := client.CompleteBundle(ctx, eventID, st.Size()); err != nil {
			warnEvent(g, err)
		}
	}

	// 12. The result.
	stdout := g.io.Out
	fmt.Fprintf(stdout, "Wrote %s (%s): %s, %s\n", out, humanSize(st.Size()), plural(len(m.Images), "image"), plural(len(m.Files), "file"))
	fmt.Fprintf(stdout, "Next: carry it across, then run: breakwater bundle load %s --docker\n", out)
	fmt.Fprintf(stdout, "      (or --registry <host>[/<prefix>] to push the images to a private registry)\n")
	return nil
}

func checkFileSizes(files []api.ManifestFile) error {
	var total int64
	for _, f := range files {
		if f.Size > maxFileSize {
			return fmt.Errorf("release file %s is %s, over the %s limit for a file in a bundle", f.Name, humanSize(f.Size), humanSize(maxFileSize))
		}
		total += f.Size
	}
	if total > maxFilesTotal {
		return fmt.Errorf("the release's files total %s, over the %s limit for a bundle", humanSize(total), humanSize(maxFilesTotal))
	}
	return nil
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func refuseExisting(out string) error {
	if _, err := os.Lstat(out); err == nil {
		return fmt.Errorf("%s already exists; use --force to overwrite it", out)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// entry is one declared bundle entry and where its bytes come from: data
// in memory, a blob of an image, or a file on disk.
type entry struct {
	path   string
	size   int64
	sha256 string
	data   []byte
	blob   *v1.Descriptor
	file   string
}

// imagePlan is an image's blobs to pull: the ones no earlier image brought.
type imagePlan struct {
	resolved *images.Resolved
	blobs    []entry
}

type bundlePlan struct {
	header bundle.Header
	front  []entry // layout, index.json, manifests
	images []imagePlan
	back   []entry // files, binaries
}

func sha256Of(b []byte) string {
	h, _, _ := v1.SHA256(bytes.NewReader(b))
	return h.Hex
}

// planBundle lays out the bundle: oci/oci-layout, oci/index.json, every
// manifest, every blob (each once across images), files and binaries.
func planBundle(m *api.Manifest, rawManifest json.RawMessage, platforms []string, resolved []*images.Resolved, files [][]byte, bins []selfdist.Binary) (*bundlePlan, error) {
	p := &bundlePlan{header: bundle.Header{
		Format:     bundle.Format,
		CLIVersion: version.Version,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		Manifest:   rawManifest,
		Platforms:  platforms,
	}}
	declared := map[string]bool{}

	layout := []byte(bundle.LayoutJSON)
	p.front = append(p.front, entry{path: bundle.LayoutPath, size: int64(len(layout)), sha256: sha256Of(layout), data: layout})

	index := v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex}
	for _, r := range resolved {
		img := r.Image
		index.Manifests = append(index.Manifests, v1.Descriptor{
			MediaType:   types.MediaType(img.MediaType),
			Size:        img.Size,
			Digest:      r.Manifests[0].Digest,
			Annotations: bundle.IndexAnnotations(img.Reference),
		})
		p.header.Images = append(p.header.Images, bundle.Image{
			Kind: img.Kind, Reference: img.Reference, Tag: img.Tag, RepositoryPath: img.RepositoryPath,
			Digest: img.Digest, MediaType: img.MediaType, Children: r.Children,
		})
	}
	indexJSON, err := json.Marshal(index)
	if err != nil {
		return nil, err
	}
	p.front = append(p.front, entry{path: bundle.IndexPath, size: int64(len(indexJSON)), sha256: sha256Of(indexJSON), data: indexJSON})
	declared[bundle.LayoutPath], declared[bundle.IndexPath] = true, true

	for _, r := range resolved {
		for _, mf := range r.Manifests {
			path, err := bundle.BlobPath(mf.Digest.String())
			if err != nil {
				return nil, fmt.Errorf("image %s: %w", r.Image.Reference, err)
			}
			if declared[path] {
				continue
			}
			declared[path] = true
			p.front = append(p.front, entry{path: path, size: int64(len(mf.Raw)), sha256: mf.Digest.Hex, data: mf.Raw})
		}
	}
	for _, r := range resolved {
		ip := imagePlan{resolved: r}
		for i := range r.Blobs {
			d := &r.Blobs[i]
			if d.Digest.Algorithm != "sha256" {
				return nil, fmt.Errorf("image %s: blob %s isn't a sha256 digest, which bundles need", r.Image.Reference, d.Digest)
			}
			path, err := bundle.BlobPath(d.Digest.String())
			if err != nil {
				return nil, fmt.Errorf("image %s: %w", r.Image.Reference, err)
			}
			if declared[path] {
				continue
			}
			declared[path] = true
			ip.blobs = append(ip.blobs, entry{path: path, size: d.Size, sha256: d.Digest.Hex, blob: d})
		}
		p.images = append(p.images, ip)
	}

	for i, f := range m.Files {
		p.back = append(p.back, entry{path: bundle.FilePath(f.Name), size: int64(len(files[i])), sha256: f.SHA256, data: files[i]})
		p.header.Files = append(p.header.Files, bundle.File{Name: f.Name, Size: f.Size, SHA256: f.SHA256})
	}
	for _, b := range bins {
		p.back = append(p.back, entry{path: bundle.BinPath(b.Name), size: b.Size, sha256: b.SHA256, file: b.Path})
		p.header.Bin = append(p.header.Bin, bundle.Bin{Name: b.Name, Platform: b.Platform, Size: b.Size, SHA256: b.SHA256})
	}
	return p, nil
}

// writeBundle writes the plan to <out>.partial, syncs it and renames it to
// out. On any failure, including a cancelled ctx, the .partial is removed
// and nothing is left at out.
func writeBundle(ctx context.Context, g *globals, col *images.Collector, p *bundlePlan, out string, force bool) (err error) {
	partial := out + ".partial"
	// O_EXCL: never reuse or follow whatever is there, symlinks included.
	f, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s exists (another bundle create running, or a stale one); remove it and try again", partial)
	}
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(partial)
		}
	}()
	bw := bufio.NewWriterSize(f, 1<<20)
	w := bundle.NewWriter(bw, p.header)
	for _, e := range p.front {
		w.Declare(e.path, e.size, e.sha256)
	}
	for _, ip := range p.images {
		for _, e := range ip.blobs {
			w.Declare(e.path, e.size, e.sha256)
		}
	}
	for _, e := range p.back {
		w.Declare(e.path, e.size, e.sha256)
	}
	if err := w.Begin(); err != nil {
		return err
	}
	for _, e := range p.front {
		if err := w.Add(e.path, bytes.NewReader(e.data)); err != nil {
			return err
		}
	}
	for _, ip := range p.images {
		var total int64
		for _, e := range ip.blobs {
			total += e.size
		}
		fmt.Fprintf(g.io.Err, "Pulling %s (%s, %s)\n", clean(ip.resolved.Image.Reference), plural(len(ip.blobs), "blob"), humanSize(total))
		for _, e := range ip.blobs {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := addBlob(ctx, w, col, ip.resolved, e); err != nil {
				return fmt.Errorf("image %s: blob %s: %w", ip.resolved.Image.Reference, e.blob.Digest, err)
			}
		}
	}
	for _, e := range p.back {
		var r io.Reader = bytes.NewReader(e.data)
		if e.file != "" {
			src, err := os.Open(e.file)
			if err != nil {
				return err
			}
			defer src.Close()
			r = src
		}
		if err := w.Add(e.path, r); err != nil {
			return err
		}
	}
	if err := w.Close(); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := publish(partial, out, force); err != nil {
		return err
	}
	syncDir(filepath.Dir(out))
	return nil
}

// publish moves the finished partial to out. With force it renames over
// out. Without, it hard-links, which fails if out exists, so nothing
// created meanwhile is overwritten; where links aren't supported it
// re-checks and renames.
func publish(partial, out string, force bool) error {
	if force {
		return os.Rename(partial, out)
	}
	err := os.Link(partial, out)
	if err == nil {
		os.Remove(partial)
		return nil
	}
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s already exists; use --force to overwrite it", out)
	}
	if err := refuseExisting(out); err != nil {
		return err
	}
	return os.Rename(partial, out)
}

func addBlob(ctx context.Context, w *bundle.Writer, col *images.Collector, r *images.Resolved, e entry) error {
	rc, err := col.FetchBlob(ctx, r, *e.blob)
	if err != nil {
		return err
	}
	defer rc.Close()
	return w.Add(e.path, rc)
}

// syncDir makes a rename durable where the platform allows it.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}
