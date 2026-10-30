// Package images resolves release images in their registries and streams
// their blobs, for bundle create.
package images

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stympy/breakwater-cli/internal/api"
	"github.com/stympy/breakwater-cli/internal/bundle"
)

// maxConfigSize caps an image config read to learn its platform.
const maxConfigSize = bundle.MaxManifestSize

// Collector resolves images and fetches their blobs. Credentials (Auth) go
// only to RegistryHost, for internal images; external images are pulled
// anonymously.
type Collector struct {
	RegistryHost string
	Auth         authn.Authenticator
	UserAgent    string
	// Transport defaults to remote.DefaultTransport.
	Transport http.RoundTripper
	// InsecureRegistries are hosts that may be reached over plain HTTP
	// (tests).
	InsecureRegistries []string
}

// RawManifest is a manifest or index as the registry served it.
type RawManifest struct {
	Digest    v1.Hash
	MediaType types.MediaType
	Raw       []byte
}

// Resolved is an image with everything a bundle needs from it.
type Resolved struct {
	Image api.ManifestImage
	Ref   name.Digest
	// Manifests are every manifest and index kept, the top-level one first,
	// each once.
	Manifests []RawManifest
	// Children are the kept child digests of an index (nil for a manifest).
	Children []string
	// Blobs are the configs and layers under the kept manifests, each once.
	Blobs []v1.Descriptor
	// Platforms are "os/arch[/variant]" of the kept manifests, from the
	// index's descriptors or, for a lone image, its config. An artifact has
	// none.
	Platforms []string

	puller *remote.Puller
}

func (c *Collector) puller(internal bool, host string) (*remote.Puller, error) {
	auth := authn.Anonymous
	if internal && c.Auth != nil {
		auth = c.Auth
	}
	t := c.Transport
	if t == nil {
		t = remote.DefaultTransport
	}
	if !slices.Contains(c.InsecureRegistries, host) {
		// ggcr falls back to plain HTTP for localhost, loopback, .local and
		// RFC 1918 hosts; only hosts listed as insecure may use it.
		t = &httpsOnly{inner: t, host: host}
	}
	opts := []remote.Option{remote.WithAuth(auth), remote.WithTransport(t)}
	if c.UserAgent != "" {
		opts = append(opts, remote.WithUserAgent(c.UserAgent))
	}
	return remote.NewPuller(opts...)
}

// httpsOnly refuses plain-HTTP requests to a registry host. Requests to
// other hosts (blob redirects to storage, which get no credentials and are
// checked by digest) pass.
type httpsOnly struct {
	inner http.RoundTripper
	host  string
}

func (t *httpsOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" && r.URL.Host == t.host {
		return nil, fmt.Errorf("refusing plain HTTP to registry %s; only hosts in --insecure-registries may use it", t.host)
	}
	return t.inner.RoundTrip(r)
}

// ref is "<reference minus :tag>@<digest>".
func (c *Collector) ref(img api.ManifestImage) (name.Digest, error) {
	tagged, err := name.ParseReference(img.Reference)
	if err != nil {
		return name.Digest{}, fmt.Errorf("image %s has an invalid reference: %w", img.Reference, err)
	}
	var opts []name.Option
	if slices.Contains(c.InsecureRegistries, tagged.Context().RegistryStr()) {
		opts = append(opts, name.Insecure)
	}
	d, err := name.NewDigest(tagged.Context().Name()+"@"+img.Digest, opts...)
	if err != nil {
		return name.Digest{}, fmt.Errorf("image %s: %w", img.Reference, err)
	}
	return d, nil
}

// Resolve fetches an image's manifests and lists its blobs. With platforms
// non-nil, an index keeps only the children for those platforms (and drops
// attestations).
func (c *Collector) Resolve(ctx context.Context, img api.ManifestImage, platforms []string) (*Resolved, error) {
	ref, err := c.ref(img)
	if err != nil {
		return nil, err
	}
	internal := img.Kind == "internal"
	if internal && ref.Context().RegistryStr() != c.RegistryHost {
		return nil, fmt.Errorf("image %s is marked internal but isn't on %s", img.Reference, c.RegistryHost)
	}
	p, err := c.puller(internal, ref.Context().RegistryStr())
	if err != nil {
		return nil, err
	}
	r := &Resolved{Image: img, Ref: ref, puller: p}
	w := &walker{ctx: ctx, r: r, what: img.Reference, seenM: map[v1.Hash]bool{}, seenB: map[v1.Hash]bool{}}

	want, err := v1.NewHash(img.Digest)
	if err != nil {
		return nil, fmt.Errorf("image %s: %w", img.Reference, err)
	}
	top := v1.Descriptor{Digest: want, Size: img.Size, MediaType: types.MediaType(img.MediaType)}
	raw, err := w.fetch(top, "")
	if err != nil {
		return nil, err
	}
	switch mt := top.MediaType; {
	case mt.IsIndex():
		err = w.index(raw, platforms)
	case mt.IsImage():
		err = w.manifest(top, raw, true)
	default:
		err = fmt.Errorf("image %s has unsupported media type %s", img.Reference, mt)
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

type walker struct {
	ctx          context.Context
	r            *Resolved
	what         string
	seenM, seenB map[v1.Hash]bool
}

// fetch gets a manifest or index by digest, checks it against d (digest,
// size, media type) and records it. what names a child in errors.
func (w *walker) fetch(d v1.Descriptor, what string) ([]byte, error) {
	label := "image " + w.what
	if what != "" {
		label += ": " + what + " " + d.Digest.String()
	}
	if isSchema1(d.MediaType) {
		return nil, fmt.Errorf("%s uses Docker schema 1, which isn't supported", label)
	}
	if d.Digest.Algorithm != "sha256" {
		return nil, fmt.Errorf("%s has a non-sha256 digest %s", label, d.Digest)
	}
	if d.Size > bundle.MaxManifestSize {
		return nil, fmt.Errorf("%s is %d bytes, over the %d byte limit for a manifest", label, d.Size, bundle.MaxManifestSize)
	}
	desc, err := w.r.puller.Get(w.ctx, w.r.Ref.Context().Digest(d.Digest.String()))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	raw := desc.Manifest
	sum := sha256.Sum256(raw)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != d.Digest.String() {
		return nil, fmt.Errorf("%s: the registry served a manifest with digest %s", label, got)
	}
	if isSchema1(desc.MediaType) {
		return nil, fmt.Errorf("%s uses Docker schema 1, which isn't supported", label)
	}
	if int64(len(raw)) != d.Size {
		return nil, fmt.Errorf("%s: the registry's manifest is %d bytes, but %d were expected", label, len(raw), d.Size)
	}
	if desc.MediaType != d.MediaType {
		return nil, fmt.Errorf("%s: the registry says media type %s, but %s was expected", label, desc.MediaType, d.MediaType)
	}
	if !w.seenM[d.Digest] {
		w.seenM[d.Digest] = true
		w.r.Manifests = append(w.r.Manifests, RawManifest{Digest: d.Digest, MediaType: d.MediaType, Raw: raw})
	}
	return raw, nil
}

func (w *walker) index(raw []byte, platforms []string) error {
	im, err := v1.ParseIndexManifest(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("image %s: its index doesn't parse: %w", w.what, err)
	}
	seen := map[v1.Hash]bool{}
	var kept []v1.Descriptor
	var available []string
	for _, d := range im.Manifests {
		if seen[d.Digest] {
			return fmt.Errorf("image %s: its index lists %s twice", w.what, d.Digest)
		}
		seen[d.Digest] = true
		attestation := bundle.IsAttestation(d)
		if p := bundle.PlatformString(d.Platform); p != "" && !attestation && !slices.Contains(available, p) {
			available = append(available, p)
		}
		if platforms == nil || (!attestation && bundle.PlatformMatches(d.Platform, platforms)) {
			kept = append(kept, d)
		}
	}
	if len(kept) == 0 {
		has := strings.Join(available, ", ")
		if has == "" {
			has = "no platforms"
		}
		return fmt.Errorf("image %s has no manifest for %s; it has %s", w.what, strings.Join(platforms, ", "), has)
	}
	for _, d := range kept {
		w.r.Children = append(w.r.Children, d.Digest.String())
		if p := bundle.PlatformString(d.Platform); p != "" && !bundle.IsAttestation(d) {
			w.addPlatform(p)
		}
		switch {
		case d.MediaType.IsIndex():
			if err := w.nested(d); err != nil {
				return err
			}
		case d.MediaType.IsImage():
			raw, err := w.fetch(d, "manifest")
			if err != nil {
				return err
			}
			if err := w.manifest(d, raw, false); err != nil {
				return err
			}
		case isSchema1(d.MediaType):
			return fmt.Errorf("image %s: manifest %s uses Docker schema 1, which isn't supported", w.what, d.Digest)
		default:
			return fmt.Errorf("image %s: child %s has unsupported media type %s", w.what, d.Digest, d.MediaType)
		}
	}
	return nil
}

// nested keeps every child of an index nested in the top-level one. They
// must be manifests.
func (w *walker) nested(d v1.Descriptor) error {
	raw, err := w.fetch(d, "index")
	if err != nil {
		return err
	}
	im, err := v1.ParseIndexManifest(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("image %s: index %s doesn't parse: %w", w.what, d.Digest, err)
	}
	seen := map[v1.Hash]bool{}
	for _, c := range im.Manifests {
		if seen[c.Digest] {
			return fmt.Errorf("image %s: index %s lists %s twice", w.what, d.Digest, c.Digest)
		}
		seen[c.Digest] = true
		if c.MediaType.IsIndex() {
			return fmt.Errorf("image %s: index %s is nested more than one level deep", w.what, c.Digest)
		}
		if !c.MediaType.IsImage() && !isSchema1(c.MediaType) {
			return fmt.Errorf("image %s: manifest %s has unsupported media type %s", w.what, c.Digest, c.MediaType)
		}
		raw, err := w.fetch(c, "manifest")
		if err != nil {
			return err
		}
		if p := bundle.PlatformString(c.Platform); p != "" && !bundle.IsAttestation(c) {
			w.addPlatform(p)
		}
		if err := w.manifest(c, raw, false); err != nil {
			return err
		}
	}
	return nil
}

// manifest records a manifest's config and layers. lone means it's the
// top-level image, whose platform comes from its config.
func (w *walker) manifest(d v1.Descriptor, raw []byte, lone bool) error {
	m, err := v1.ParseManifest(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("image %s: manifest %s doesn't parse: %w", w.what, d.Digest, err)
	}
	for _, b := range append([]v1.Descriptor{m.Config}, m.Layers...) {
		if b.Digest.Algorithm != "sha256" {
			return fmt.Errorf("image %s: blob %s isn't a sha256 digest, which bundles need", w.what, b.Digest)
		}
		if b.Size < 0 {
			return fmt.Errorf("image %s: blob %s has an invalid size %d", w.what, b.Digest, b.Size)
		}
		if !w.seenB[b.Digest] {
			w.seenB[b.Digest] = true
			w.r.Blobs = append(w.r.Blobs, b)
		}
	}
	if lone && isImageConfig(m.Config.MediaType) && m.Config.Size <= maxConfigSize {
		p, err := w.configPlatform(m.Config)
		if err != nil {
			return err
		}
		if p != "" {
			w.addPlatform(p)
		}
	}
	return nil
}

func isSchema1(mt types.MediaType) bool {
	return mt == types.DockerManifestSchema1 || mt == types.DockerManifestSchema1Signed
}

func isImageConfig(mt types.MediaType) bool {
	return mt == types.OCIConfigJSON || mt == types.DockerConfigJSON
}

// configPlatform reads a lone image's config for its platform.
func (w *walker) configPlatform(d v1.Descriptor) (string, error) {
	rc, err := fetchBlob(w.ctx, w.r, d)
	if err != nil {
		return "", fmt.Errorf("image %s: config %s: %w", w.what, d.Digest, err)
	}
	defer rc.Close()
	raw, err := io.ReadAll(io.LimitReader(rc, maxConfigSize))
	if err != nil {
		return "", fmt.Errorf("image %s: config %s: %w", w.what, d.Digest, err)
	}
	cf, err := v1.ParseConfigFile(bytes.NewReader(raw))
	if err != nil || cf.OS == "" || cf.Architecture == "" {
		return "", nil // not an image config after all: no platform
	}
	return bundle.PlatformString(&v1.Platform{OS: cf.OS, Architecture: cf.Architecture, Variant: cf.Variant}), nil
}

func (w *walker) addPlatform(p string) {
	if !slices.Contains(w.r.Platforms, p) {
		w.r.Platforms = append(w.r.Platforms, p)
	}
}

// FetchBlob streams a config or layer of a resolved image from its
// repository, by digest, with the same credentials rule as Resolve. Foreign
// layers are fetched from the registry like any other. The caller checks
// the digest of what it reads.
func (c *Collector) FetchBlob(ctx context.Context, r *Resolved, d v1.Descriptor) (io.ReadCloser, error) {
	return fetchBlob(ctx, r, d)
}

func fetchBlob(ctx context.Context, r *Resolved, d v1.Descriptor) (io.ReadCloser, error) {
	l, err := r.puller.Layer(ctx, r.Ref.Context().Digest(d.Digest.String()))
	if err != nil {
		return nil, err
	}
	return l.Compressed()
}
