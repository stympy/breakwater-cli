// Package load loads a verified bundle's images into Docker or pushes them
// to a registry, and rewrites the bundle's compose and YAML files to the
// names the images got.
//
// Everything here takes a *bundle.Bundle, which only bundle.Open returns,
// after the whole bundle has been verified. Bundle contents are still read
// through Bundle.Blob and File, which re-check digests, and are treated as
// hostile: names come from the validated bundle.json, never from the
// bundle's oci/index.json, and text from the bundle is cleaned before it's
// printed.
package load

import (
	"bytes"
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stympy/breakwater-cli/internal/bundle"
)

// maxConfigSize caps an image config read into memory.
const maxConfigSize = 16 << 20

// Mapping is where one bundle image went: From is its reference in the
// release, To the name it was pushed or loaded as. FromDigest is the
// release's digest and ToDigest the digest under To, which differs when the
// bundle keeps only some of an index's platforms.
type Mapping struct {
	From, To             string
	FromDigest, ToDigest string
}

// DockerName normalizes a reference the way Docker does: the registry host
// is always present ("docker.io" for Docker Hub), Docker Hub's official
// images get "library/", and a missing tag is "latest". A reference with a
// digest is refused.
func DockerName(ref string) (string, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "", err
	}
	t, ok := r.(name.Tag)
	if !ok {
		return "", fmt.Errorf("%q has a digest", ref)
	}
	reg := t.RegistryStr()
	if reg == name.DefaultRegistry {
		reg = "docker.io"
	}
	return reg + "/" + t.RepositoryStr() + ":" + t.TagStr(), nil
}

// readBlob reads a whole blob of at most max bytes, checking its digest.
func readBlob(b *bundle.Bundle, digest string, max int64) ([]byte, error) {
	rc, err := b.Blob(digest)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(rc, max+1))
	cerr := rc.Close()
	if err != nil {
		return nil, err
	}
	if cerr != nil {
		return nil, cerr
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("blob %s is over the %d MiB limit for it", digest, max>>20)
	}
	return raw, nil
}

func readIndex(b *bundle.Bundle, digest string) ([]byte, *v1.IndexManifest, error) {
	raw, err := readBlob(b, digest, bundle.MaxManifestSize)
	if err != nil {
		return nil, nil, err
	}
	im, err := v1.ParseIndexManifest(bytes.NewReader(raw))
	if err != nil {
		return nil, nil, fmt.Errorf("index %s doesn't parse: %w", digest, err)
	}
	return raw, im, nil
}

func readManifest(b *bundle.Bundle, digest string) ([]byte, *v1.Manifest, error) {
	raw, err := readBlob(b, digest, bundle.MaxManifestSize)
	if err != nil {
		return nil, nil, err
	}
	m, err := v1.ParseManifest(bytes.NewReader(raw))
	if err != nil {
		return nil, nil, fmt.Errorf("manifest %s doesn't parse: %w", digest, err)
	}
	return raw, m, nil
}

// keptChildren are an index's descriptors for the children the bundle
// keeps, in index order.
func keptChildren(img bundle.Image, im *v1.IndexManifest) []v1.Descriptor {
	keep := make(map[string]bool, len(img.Children))
	for _, c := range img.Children {
		keep[c] = true
	}
	var out []v1.Descriptor
	for _, d := range im.Manifests {
		if keep[d.Digest.String()] {
			out = append(out, d)
		}
	}
	return out
}

// blobLayer is a bundle blob as a ggcr compressed layer. Compressed reads
// through Bundle.Blob, so a blob that changed since it was verified fails
// the read that reaches its end, which aborts the upload or the tar.
type blobLayer struct {
	b *bundle.Bundle
	d v1.Descriptor
}

func (l *blobLayer) Digest() (v1.Hash, error)            { return l.d.Digest, nil }
func (l *blobLayer) Size() (int64, error)                { return l.d.Size, nil }
func (l *blobLayer) MediaType() (types.MediaType, error) { return l.d.MediaType, nil }
func (l *blobLayer) Compressed() (io.ReadCloser, error)  { return l.b.Blob(l.d.Digest.String()) }

// rawTaggable is a manifest or index to put as is.
type rawTaggable struct {
	raw []byte
	mt  types.MediaType
}

func (r rawTaggable) RawManifest() ([]byte, error)        { return r.raw, nil }
func (r rawTaggable) MediaType() (types.MediaType, error) { return r.mt, nil }

func isImageConfig(mt types.MediaType) bool {
	return mt == types.OCIConfigJSON || mt == types.DockerConfigJSON
}
