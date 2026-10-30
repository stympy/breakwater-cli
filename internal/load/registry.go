package load

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stympy/breakwater-cli/internal/bundle"
	"github.com/stympy/breakwater-cli/internal/images"
	"github.com/stympy/breakwater-cli/internal/term"
	"github.com/stympy/breakwater-cli/internal/version"
)

// TargetName is the name an image gets under registry ("host[/prefix]"):
// an internal image keeps its repository path and tag, and an external one
// keeps its whole Docker-normalized reference, registry host first, so
// "postgres:16.4" becomes "<registry>/docker.io/library/postgres:16.4". It
// returns "" when the image's reference doesn't parse. The result still
// needs checking with name.ParseReference: an external image on a registry
// with a port gives no valid name.
func TargetName(img bundle.Image, registry string) string {
	if img.Kind == "internal" {
		return registry + "/" + img.RepositoryPath + ":" + img.Tag
	}
	n, err := DockerName(img.Reference)
	if err != nil {
		return ""
	}
	return registry + "/" + n
}

// checkRegistry checks --registry: a host, optionally a port, and an
// optional repository prefix, with no scheme, tag or trailing slash.
func checkRegistry(registry string) (string, error) {
	if registry == "" {
		return "", errors.New("--registry needs a host, like registry.example.com or registry.example.com/prefix")
	}
	if strings.Contains(registry, "://") {
		return "", fmt.Errorf("--registry %q: give host[/prefix], without a scheme", registry)
	}
	host, prefix, hasPrefix := strings.Cut(registry, "/")
	if _, err := name.NewRegistry(host, name.StrictValidation); err != nil || strings.Contains(host, "@") {
		return "", fmt.Errorf("--registry %q: invalid host %q", registry, host)
	}
	if hasPrefix {
		if _, err := name.NewRepository(registry+"/x", name.StrictValidation); err != nil || prefix == "" {
			return "", fmt.Errorf("--registry %q: invalid repository prefix %q (use lowercase path segments, like mirror/acme)", registry, prefix)
		}
	}
	return host, nil
}

type target struct {
	img bundle.Image
	tag name.Tag
}

// ToRegistry pushes every image in the bundle to registry ("host[/prefix]",
// named by TargetName) and prints "<from> -> <to>@<digest>" for each to
// out. Blobs and child manifests are pushed by digest, then the top level
// under the tag: as is when the bundle keeps all of it (so its digest is
// unchanged), the one kept child when an index keeps one, or a new index
// listing the kept children. auth may be nil (anonymous). The registry is
// reached over HTTPS only unless insecure is set.
func ToRegistry(ctx context.Context, b *bundle.Bundle, registry string, auth authn.Authenticator, insecure bool, out io.Writer) ([]Mapping, error) {
	host, err := checkRegistry(registry)
	if err != nil {
		return nil, err
	}
	var nameOpts []name.Option
	if insecure {
		nameOpts = append(nameOpts, name.Insecure)
	}

	// Name every image before pushing anything.
	var targets []target
	seen := map[string]bundle.Image{}
	for _, img := range b.Header().Images {
		to := TargetName(img, registry)
		tag, err := name.NewTag(to, nameOpts...)
		if err != nil || to == "" || tag.RegistryStr() != host {
			return nil, fmt.Errorf("image %s can't be named under %s", term.Clean(img.Reference), registry)
		}
		if prev, ok := seen[tag.Name()]; ok && (prev.Digest != img.Digest || !slices.Equal(prev.Children, img.Children)) {
			return nil, fmt.Errorf("images %s and %s would both be pushed as %s", term.Clean(prev.Reference), term.Clean(img.Reference), to)
		}
		seen[tag.Name()] = img
		targets = append(targets, target{img, tag})
	}

	if auth == nil {
		auth = authn.Anonymous
	}
	transport := remote.DefaultTransport
	if !insecure {
		transport = images.HTTPSOnly(transport, host, "pass --insecure to allow it")
	}
	p := &pusher{
		b:      b,
		pushed: map[string]bool{},
		opts: []remote.Option{
			remote.WithContext(ctx),
			remote.WithAuth(auth),
			remote.WithTransport(transport),
			remote.WithUserAgent(version.UserAgent()),
			remote.WithNondistributable, // the bundle carries foreign layers; the target needs them
		},
	}

	var mappings []Mapping
	changed := 0
	for _, t := range targets {
		toDigest, err := p.image(t)
		if err != nil {
			return mappings, fmt.Errorf("pushing %s to %s: %w", term.Clean(t.img.Reference), t.tag, err)
		}
		m := Mapping{From: t.img.Reference, To: t.tag.String(), FromDigest: t.img.Digest, ToDigest: toDigest}
		mappings = append(mappings, m)
		if m.ToDigest != m.FromDigest {
			changed++
		}
		fmt.Fprintf(out, "%s -> %s@%s\n", term.Clean(m.From), m.To, m.ToDigest)
	}
	if changed > 0 {
		fmt.Fprintf(out, "note: %d image(s) got a new digest because the bundle keeps only some platforms; use --rewrite-files for files that pin digests.\n", changed)
	}
	return mappings, nil
}

type pusher struct {
	b      *bundle.Bundle
	opts   []remote.Option
	pushed map[string]bool // "<repository>@<digest>" of blobs and manifests already pushed
}

// image pushes one bundle image and returns the digest under its tag.
func (p *pusher) image(t target) (string, error) {
	repo := t.tag.Context()
	hash, err := v1.NewHash(t.img.Digest)
	if err != nil {
		return "", err
	}
	mt := types.MediaType(t.img.MediaType)
	if mt.IsImage() {
		raw, err := p.tree(repo, v1.Descriptor{Digest: hash, MediaType: mt})
		if err != nil {
			return "", err
		}
		return t.img.Digest, p.put(t.tag, raw, mt)
	}

	raw, im, err := readIndex(p.b, t.img.Digest)
	if err != nil {
		return "", err
	}
	kept := keptChildren(t.img, im)
	if len(kept) == 0 {
		return "", errors.New("the bundle keeps none of its index's children")
	}
	for _, c := range kept {
		if err := p.child(repo, c); err != nil {
			return "", err
		}
	}
	switch {
	case len(kept) == len(im.Manifests):
		return t.img.Digest, p.put(t.tag, raw, mt)
	case len(kept) == 1:
		childRaw, err := readBlob(p.b, kept[0].Digest.String(), bundle.MaxManifestSize)
		if err != nil {
			return "", err
		}
		return kept[0].Digest.String(), p.put(t.tag, childRaw, kept[0].MediaType)
	default:
		filtered, err := filterIndex(raw, kept)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(filtered)
		return "sha256:" + hex.EncodeToString(sum[:]), p.put(t.tag, filtered, mt)
	}
}

func (p *pusher) put(ref name.Reference, raw []byte, mt types.MediaType) error {
	return remote.Put(ref, rawTaggable{raw: raw, mt: mt}, p.opts...)
}

// tree pushes everything under a manifest or index (not the manifest or
// index itself) and returns its raw bytes.
func (p *pusher) tree(repo name.Repository, d v1.Descriptor) ([]byte, error) {
	switch {
	case d.MediaType.IsIndex():
		raw, im, err := readIndex(p.b, d.Digest.String())
		if err != nil {
			return nil, err
		}
		for _, c := range im.Manifests {
			if err := p.child(repo, c); err != nil {
				return nil, err
			}
		}
		return raw, nil
	case d.MediaType.IsImage():
		raw, m, err := readManifest(p.b, d.Digest.String())
		if err != nil {
			return nil, err
		}
		for _, bd := range append([]v1.Descriptor{m.Config}, m.Layers...) {
			if err := p.blob(repo, bd); err != nil {
				return nil, err
			}
		}
		return raw, nil
	default:
		return nil, fmt.Errorf("%s has unsupported media type %s", d.Digest, d.MediaType)
	}
}

// child pushes a manifest or index and everything under it, by digest.
func (p *pusher) child(repo name.Repository, d v1.Descriptor) error {
	key := repo.Name() + "@" + d.Digest.String()
	if p.pushed[key] {
		return nil
	}
	raw, err := p.tree(repo, d)
	if err != nil {
		return err
	}
	if err := p.put(repo.Digest(d.Digest.String()), raw, d.MediaType); err != nil {
		return fmt.Errorf("manifest %s: %w", d.Digest, err)
	}
	p.pushed[key] = true
	return nil
}

// blob pushes a config or layer from the bundle; ggcr skips one the
// registry already has.
func (p *pusher) blob(repo name.Repository, d v1.Descriptor) error {
	key := repo.Name() + "@" + d.Digest.String()
	if p.pushed[key] {
		return nil
	}
	l, err := partial.CompressedToLayer(&blobLayer{b: p.b, d: d})
	if err != nil {
		return err
	}
	if err := remote.WriteLayer(repo, l, p.opts...); err != nil {
		return fmt.Errorf("blob %s: %w", d.Digest, err)
	}
	p.pushed[key] = true
	return nil
}

// filterIndex is raw with "manifests" cut down to the kept children; every
// other field, and each kept descriptor, is as it was.
func filterIndex(raw []byte, kept []v1.Descriptor) ([]byte, error) {
	keep := map[string]bool{}
	for _, d := range kept {
		keep[d.Digest.String()] = true
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("its index doesn't parse: %w", err)
	}
	var manifests []json.RawMessage
	if err := json.Unmarshal(doc["manifests"], &manifests); err != nil {
		return nil, fmt.Errorf("its index's manifests don't parse: %w", err)
	}
	var out []json.RawMessage
	for _, m := range manifests {
		var d struct {
			Digest string `json:"digest"`
		}
		if err := json.Unmarshal(m, &d); err != nil {
			return nil, fmt.Errorf("its index's manifests don't parse: %w", err)
		}
		if keep[d.Digest] {
			out = append(out, m)
		}
	}
	if len(out) != len(kept) {
		return nil, errors.New("its index doesn't list each kept child once")
	}
	list, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	doc["manifests"] = list
	return json.Marshal(doc)
}
