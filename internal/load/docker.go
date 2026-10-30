package load

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stympy/breakwater-cli/internal/bundle"
	"github.com/stympy/breakwater-cli/internal/term"
)

// Skipped is a bundle image ToDocker didn't load, and why.
type Skipped struct {
	Reference, Reason string
}

var dockerPlatformPattern = regexp.MustCompile(`^[a-z0-9_]+/[a-z0-9_]+$`)

// ToDocker loads the bundle's container images into Docker, through
// dockerCmd ("docker" if empty). Each image is loaded for platform
// ("os/arch[/variant]"), or Docker's own when platform is "", named by its
// Docker-normalized release reference. Artifacts that
// aren't container images, and indexes with no manifest for Docker's
// platform, are skipped. The images are streamed as one docker-archive into
// "docker load"; nothing is loaded when nothing is left. Loaded names and
// skipped images are printed to out.
func ToDocker(ctx context.Context, b *bundle.Bundle, dockerCmd, platform string, out io.Writer) ([]Mapping, []Skipped, error) {
	if dockerCmd == "" {
		dockerCmd = "docker"
	}
	if platform == "" {
		var err error
		if platform, err = dockerPlatform(ctx, dockerCmd); err != nil {
			return nil, nil, err
		}
	} else if !bundle.ValidPlatform(platform) {
		return nil, nil, fmt.Errorf("invalid platform %q: use os/arch or os/arch/variant, like linux/amd64", platform)
	}

	var (
		mappings []Mapping
		skipped  []Skipped
		refs     = map[name.Reference]v1.Image{}
		byName   = map[string]bundle.Image{}
		chosen   = map[string]string{} // name -> manifest digest
		built    = map[string]v1.Image{}
	)
	for _, img := range b.Header().Images {
		to, err := DockerName(img.Reference)
		if err != nil {
			return nil, nil, fmt.Errorf("image %s has an invalid reference: %w", term.Clean(img.Reference), err)
		}
		d, ok, err := chooseManifest(b, img, platform)
		if err != nil {
			return nil, nil, fmt.Errorf("image %s: %w", term.Clean(img.Reference), err)
		}
		if !ok {
			skipped = append(skipped, Skipped{img.Reference, fmt.Sprintf("no %s manifest in bundle", platform)})
			continue
		}
		raw, m, err := readManifest(b, d.Digest.String())
		if err != nil {
			return nil, nil, fmt.Errorf("image %s: %w", term.Clean(img.Reference), err)
		}
		if !isImageConfig(m.Config.MediaType) {
			skipped = append(skipped, Skipped{img.Reference, fmt.Sprintf("not a container image (%s)", m.Config.MediaType)})
			continue
		}
		if prev, ok := byName[to]; ok {
			if chosen[to] != d.Digest.String() {
				return nil, nil, fmt.Errorf("images %s and %s would both be loaded as %s", term.Clean(prev.Reference), term.Clean(img.Reference), to)
			}
			continue // the same image again: loaded once
		}
		byName[to] = img
		chosen[to] = d.Digest.String()
		tag, err := name.NewTag(to)
		if err != nil {
			return nil, nil, fmt.Errorf("image %s: %w", term.Clean(img.Reference), err)
		}
		vimg, ok := built[d.Digest.String()]
		if !ok {
			cfg, err := readBlob(b, m.Config.Digest.String(), maxConfigSize)
			if err != nil {
				return nil, nil, fmt.Errorf("image %s: config: %w", term.Clean(img.Reference), err)
			}
			vimg, err = partial.CompressedToImage(&bundleImage{b: b, raw: raw, mt: d.MediaType, m: m, cfg: cfg})
			if err != nil {
				return nil, nil, err
			}
			built[d.Digest.String()] = vimg
		}
		refs[tag] = vimg
		mappings = append(mappings, Mapping{From: img.Reference, To: to, FromDigest: img.Digest, ToDigest: d.Digest.String()})
	}

	if len(refs) > 0 {
		if err := dockerLoad(ctx, dockerCmd, refs); err != nil {
			return nil, skipped, err
		}
	}
	for _, m := range mappings {
		fmt.Fprintf(out, "Loaded %s\n", term.Clean(m.To))
	}
	for _, s := range skipped {
		fmt.Fprintf(out, "Skipped %s: %s\n", term.Clean(s.Reference), term.Clean(s.Reason))
	}
	return mappings, skipped, nil
}

// chooseManifest picks an image's manifest for platform: a lone manifest as
// is, or the manifest the bundle keeps for it among the index's children
// and the children of any index nested in it (ok is false if none).
func chooseManifest(b *bundle.Bundle, img bundle.Image, platform string) (v1.Descriptor, bool, error) {
	hash, err := v1.NewHash(img.Digest)
	if err != nil {
		return v1.Descriptor{}, false, err
	}
	mt := types.MediaType(img.MediaType)
	if mt.IsImage() {
		return v1.Descriptor{Digest: hash, MediaType: mt}, true, nil
	}
	_, im, err := readIndex(b, img.Digest)
	if err != nil {
		return v1.Descriptor{}, false, err
	}
	var candidates []v1.Descriptor
	for _, c := range keptChildren(img, im) {
		if !c.MediaType.IsIndex() {
			candidates = append(candidates, c)
			continue
		}
		// A kept nested index is kept whole, and its children are manifests.
		_, nested, err := readIndex(b, c.Digest.String())
		if err != nil {
			return v1.Descriptor{}, false, err
		}
		candidates = append(candidates, nested.Manifests...)
	}
	d, ok := pickChild(candidates, platform)
	return d, ok, nil
}

// pickChild picks the image manifest for platform ("os/arch" as Docker
// reports it, or "os/arch/variant" from --platform) among an index's
// children, skipping attestations. OS and architecture must match. A
// requested variant must match too (on arm64, no variant means v8).
// Otherwise an arm64 host prefers v8, any other host a child with no
// variant, and failing that the first match wins.
func pickChild(children []v1.Descriptor, platform string) (v1.Descriptor, bool) {
	parts := strings.SplitN(platform, "/", 3)
	goos, arch := parts[0], ""
	if len(parts) > 1 {
		arch = parts[1]
	}
	want, exact := "", len(parts) == 3
	if exact {
		want = parts[2]
	}
	variant := func(v string) string {
		if arch == "arm64" && v == "" {
			return "v8"
		}
		return v
	}
	want = variant(want)
	var first *v1.Descriptor
	for i, c := range children {
		if !c.MediaType.IsImage() || bundle.IsAttestation(c) || c.Platform == nil || c.Platform.OS != goos || c.Platform.Architecture != arch {
			continue
		}
		if variant(c.Platform.Variant) == want {
			return c, true
		}
		if first == nil && !exact {
			first = &children[i]
		}
	}
	if first == nil {
		return v1.Descriptor{}, false
	}
	return *first, true
}

// dockerPlatform asks Docker for its server's "os/arch".
func dockerPlatform(ctx context.Context, dockerCmd string) (string, error) {
	cmd := exec.CommandContext(ctx, dockerCmd, "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}")
	var stdout, stderr capped
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("couldn't get Docker's platform with %q (is Docker running?): %v %s", dockerCmd, err, term.Clean(strings.TrimSpace(stderr.String())))
	}
	p := strings.TrimSpace(stdout.String())
	if !dockerPlatformPattern.MatchString(p) {
		return "", fmt.Errorf("docker version reported an unexpected platform %q", term.Clean(p))
	}
	return p, nil
}

// dockerLoad streams the images as one docker-archive into "docker load".
// The archive's manifest.json, which docker load needs to load anything, is
// its last entry, so if writing fails partway (a blob that changed since
// the bundle was verified) docker never gets a loadable archive. Docker is
// also killed before its stdin closes, so it doesn't spend time on the
// partial archive.
func dockerLoad(ctx context.Context, dockerCmd string, refs map[name.Reference]v1.Image) error {
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, dockerCmd, "load")
	var output capped
	cmd.Stdin, cmd.Stdout, cmd.Stderr = r, &output, &output
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		r.Close()
		w.Close()
		return fmt.Errorf("starting docker load: %w", err)
	}
	r.Close()
	werr := tarball.MultiRefWrite(refs, w)
	if werr != nil {
		_ = cmd.Process.Kill()
	}
	w.Close()
	waitErr := cmd.Wait()
	switch {
	case werr != nil && !errors.Is(werr, syscall.EPIPE):
		return fmt.Errorf("writing the images to docker load: %w", werr)
	case waitErr != nil:
		return fmt.Errorf("docker load failed: %v: %s", waitErr, term.Clean(strings.TrimSpace(output.String())))
	case werr != nil:
		return fmt.Errorf("docker load stopped reading: %w", werr)
	}
	return nil
}

// capped keeps the first 8 KiB written to it.
type capped struct{ b []byte }

func (c *capped) Write(p []byte) (int, error) {
	if room := 8<<10 - len(c.b); room > 0 {
		c.b = append(c.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

func (c *capped) String() string { return string(c.b) }

// bundleImage is an image manifest in the bundle as a ggcr compressed
// image, for tarball.
type bundleImage struct {
	b   *bundle.Bundle
	raw []byte
	mt  types.MediaType
	m   *v1.Manifest
	cfg []byte
}

func (i *bundleImage) RawConfigFile() ([]byte, error)      { return i.cfg, nil }
func (i *bundleImage) MediaType() (types.MediaType, error) { return i.mt, nil }
func (i *bundleImage) RawManifest() ([]byte, error)        { return i.raw, nil }

func (i *bundleImage) LayerByDigest(h v1.Hash) (partial.CompressedLayer, error) {
	if h == i.m.Config.Digest {
		return &blobLayer{b: i.b, d: i.m.Config}, nil
	}
	for _, l := range i.m.Layers {
		if l.Digest == h {
			return &blobLayer{b: i.b, d: l}, nil
		}
	}
	return nil, fmt.Errorf("manifest has no blob %s", h)
}
