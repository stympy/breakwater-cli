// Package bundletest builds bundles for tests: valid ones with the real
// Writer, tampered ones through hooks, and corrupted copies. It's a normal
// package so tests in other packages can use it.
package bundletest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stympy/breakwater-cli/internal/api"
	"github.com/stympy/breakwater-cli/internal/bundle"
)

// Defaults used when Options leaves them empty.
const (
	CreatedAt  = "2026-10-30T12:00:00Z"
	CLIVersion = "0.1.0"
	Version    = "2.4.1"
)

// Image is a release image. Set exactly one of Image and Index.
type Image struct {
	Kind           string // default "internal"
	Reference      string // without a digest; default registry.breakwaterapp.com/acme/api:2.4.1
	Tag            string // default: the reference's tag
	RepositoryPath string // default: the reference's path, for internal images
	Image          v1.Image
	Index          v1.ImageIndex
	Children       []v1.Hash // index children to keep; nil keeps them all
}

// File is a release file.
type File struct {
	Name string
	Data []byte
}

// Bin is a breakwater binary carried in the bundle.
type Bin struct {
	Name, Platform string
	Data           []byte
}

// Options describe a bundle. The hooks tamper with it for tests of
// validation; the Writer still checks sizes and digests of what's written.
type Options struct {
	Platforms []string
	Images    []Image
	Files     []File
	Bin       []Bin

	EditManifest  func(*api.Manifest)     // before it's embedded in bundle.json
	EditHeader    func(*bundle.Header)    // after the manifest is embedded
	EditIndexJSON func(*v1.IndexManifest) // oci/index.json
	Omit          []string                // digests ("sha256:...") or entry paths to leave out
	Extra         map[string][]byte       // more entries, written last
}

// RandomImage is a small random single-platform image.
func RandomImage(t testing.TB) v1.Image {
	t.Helper()
	img, err := random.Image(256, 2)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

// PlatformIndex is an OCI index of one random image per platform
// ("os/arch[/variant]").
func PlatformIndex(t testing.TB, platforms ...string) v1.ImageIndex {
	t.Helper()
	var adds []mutate.IndexAddendum
	for _, p := range platforms {
		plat, err := v1.ParsePlatform(p)
		if err != nil {
			t.Fatal(err)
		}
		adds = append(adds, mutate.IndexAddendum{Add: RandomImage(t), Descriptor: v1.Descriptor{Platform: plat}})
	}
	return mutate.AppendManifests(empty.Index, adds...)
}

// Build writes a bundle to a new file under t.TempDir and returns its path.
func Build(t testing.TB, opts Options) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.tar")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := Write(f, opts); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

type pending struct {
	path string
	data []byte
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Write writes the bundle opts describe to w.
func Write(w io.Writer, opts Options) error {
	b := &builder{seen: map[string]bool{}}
	m := api.Manifest{
		Format:      1,
		Vendor:      api.ProductRef{Name: "Acme", Slug: "acme"},
		Product:     api.ProductRef{Name: "API Server", Slug: "api"},
		Version:     Version,
		PublishedAt: "2026-10-29T00:00:00Z",
		Registry:    "registry.breakwaterapp.com",
		Images:      []api.ManifestImage{},
		Files:       []api.ManifestFile{},
	}
	h := bundle.Header{CLIVersion: CLIVersion, CreatedAt: CreatedAt, Platforms: opts.Platforms}
	index := v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex}

	for _, img := range opts.Images {
		hi, mi, desc, err := b.image(img)
		if err != nil {
			return err
		}
		h.Images = append(h.Images, hi)
		m.Images = append(m.Images, mi)
		desc.Annotations = bundle.IndexAnnotations(hi.Reference)
		index.Manifests = append(index.Manifests, desc)
	}
	for _, f := range opts.Files {
		s := sum(f.Data)
		m.Files = append(m.Files, api.ManifestFile{Name: f.Name, Size: int64(len(f.Data)), SHA256: s, URL: "https://app.breakwaterapp.com/files/" + f.Name})
		h.Files = append(h.Files, bundle.File{Name: f.Name, Size: int64(len(f.Data)), SHA256: s})
	}
	for _, x := range opts.Bin {
		h.Bin = append(h.Bin, bundle.Bin{Name: x.Name, Platform: x.Platform, Size: int64(len(x.Data)), SHA256: sum(x.Data)})
	}

	if opts.EditManifest != nil {
		opts.EditManifest(&m)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	h.Manifest = raw
	if opts.EditHeader != nil {
		opts.EditHeader(&h)
	}
	if opts.EditIndexJSON != nil {
		opts.EditIndexJSON(&index)
	}
	indexJSON, err := json.Marshal(index)
	if err != nil {
		return err
	}

	entries := []pending{{bundle.LayoutPath, []byte(bundle.LayoutJSON)}, {bundle.IndexPath, indexJSON}}
	entries = append(entries, b.blobs...)
	for _, f := range opts.Files {
		entries = append(entries, pending{bundle.FilePath(f.Name), f.Data})
	}
	for _, x := range opts.Bin {
		entries = append(entries, pending{bundle.BinPath(x.Name), x.Data})
	}
	extra := make([]string, 0, len(opts.Extra))
	for p := range opts.Extra {
		extra = append(extra, p)
	}
	slices.Sort(extra)
	for _, p := range extra {
		entries = append(entries, pending{p, opts.Extra[p]})
	}
	entries = slices.DeleteFunc(entries, func(p pending) bool {
		return slices.ContainsFunc(opts.Omit, func(o string) bool {
			return o == p.path || (strings.HasPrefix(o, "sha256:") && p.path == bundle.BlobDir+strings.TrimPrefix(o, "sha256:"))
		})
	})

	bw := bundle.NewWriter(w, h)
	for _, e := range entries {
		bw.Declare(e.path, int64(len(e.data)), sum(e.data))
	}
	if err := bw.Begin(); err != nil {
		return err
	}
	for _, e := range entries {
		if err := bw.Add(e.path, bytes.NewReader(e.data)); err != nil {
			return err
		}
	}
	return bw.Close()
}

type builder struct {
	blobs []pending
	seen  map[string]bool
}

func (b *builder) add(data []byte) {
	p := bundle.BlobDir + sum(data)
	if !b.seen[p] {
		b.seen[p] = true
		b.blobs = append(b.blobs, pending{p, data})
	}
}

func (b *builder) addImage(img v1.Image) error {
	raw, err := img.RawManifest()
	if err != nil {
		return err
	}
	b.add(raw)
	cfg, err := img.RawConfigFile()
	if err != nil {
		return err
	}
	b.add(cfg)
	layers, err := img.Layers()
	if err != nil {
		return err
	}
	for _, l := range layers {
		rc, err := l.Compressed()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return err
		}
		b.add(data)
	}
	return nil
}

func (b *builder) addIndex(idx v1.ImageIndex, keep []v1.Hash, nested bool) error {
	raw, err := idx.RawManifest()
	if err != nil {
		return err
	}
	b.add(raw)
	im, err := idx.IndexManifest()
	if err != nil {
		return err
	}
	for _, d := range im.Manifests {
		if keep != nil && !slices.Contains(keep, d.Digest) {
			continue
		}
		switch {
		case d.MediaType.IsIndex() && !nested:
			child, err := idx.ImageIndex(d.Digest)
			if err != nil {
				return err
			}
			if err := b.addIndex(child, nil, true); err != nil {
				return err
			}
		case d.MediaType.IsImage():
			child, err := idx.Image(d.Digest)
			if err != nil {
				return err
			}
			if err := b.addImage(child); err != nil {
				return err
			}
		default:
			return fmt.Errorf("bundletest: unsupported child media type %s", d.MediaType)
		}
	}
	return nil
}

func (b *builder) image(img Image) (bundle.Image, api.ManifestImage, v1.Descriptor, error) {
	if img.Kind == "" {
		img.Kind = "internal"
	}
	if img.Reference == "" {
		img.Reference = "registry.breakwaterapp.com/acme/api:" + Version
	}
	slash := strings.LastIndex(img.Reference, "/")
	colon := strings.LastIndex(img.Reference, ":")
	if img.Tag == "" && colon > slash {
		img.Tag = img.Reference[colon+1:]
	}
	if img.RepositoryPath == "" && img.Kind == "internal" {
		end := len(img.Reference)
		if colon > slash {
			end = colon
		}
		img.RepositoryPath = img.Reference[strings.Index(img.Reference, "/")+1 : end]
	}

	var (
		raw      []byte
		mt       types.MediaType
		children []string
		err      error
	)
	switch {
	case img.Image != nil:
		if raw, err = img.Image.RawManifest(); err != nil {
			return bundle.Image{}, api.ManifestImage{}, v1.Descriptor{}, err
		}
		if mt, err = img.Image.MediaType(); err != nil {
			return bundle.Image{}, api.ManifestImage{}, v1.Descriptor{}, err
		}
		err = b.addImage(img.Image)
	case img.Index != nil:
		if raw, err = img.Index.RawManifest(); err != nil {
			return bundle.Image{}, api.ManifestImage{}, v1.Descriptor{}, err
		}
		if mt, err = img.Index.MediaType(); err != nil {
			return bundle.Image{}, api.ManifestImage{}, v1.Descriptor{}, err
		}
		im, ierr := img.Index.IndexManifest()
		if ierr != nil {
			return bundle.Image{}, api.ManifestImage{}, v1.Descriptor{}, ierr
		}
		for _, d := range im.Manifests {
			if img.Children == nil || slices.Contains(img.Children, d.Digest) {
				children = append(children, d.Digest.String())
			}
		}
		err = b.addIndex(img.Index, img.Children, false)
	default:
		err = fmt.Errorf("bundletest: image %s has neither Image nor Index", img.Reference)
	}
	if err != nil {
		return bundle.Image{}, api.ManifestImage{}, v1.Descriptor{}, err
	}
	digest := "sha256:" + sum(raw)
	hash, _ := v1.NewHash(digest)
	hi := bundle.Image{Kind: img.Kind, Reference: img.Reference, Tag: img.Tag, RepositoryPath: img.RepositoryPath, Digest: digest, MediaType: string(mt), Children: children}
	mi := api.ManifestImage{Kind: img.Kind, Reference: img.Reference, Digest: digest, MediaType: string(mt), Size: int64(len(raw)), RepositoryPath: img.RepositoryPath, Tag: img.Tag}
	return hi, mi, v1.Descriptor{MediaType: mt, Digest: hash, Size: int64(len(raw))}, nil
}

// Corrupt copies the bundle at path to a new file with one byte of entry's
// data flipped, and returns the copy's path.
func Corrupt(t testing.TB, path, entry string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "corrupt.tar")
	if err := os.WriteFile(out, data, 0o644); err != nil {
		t.Fatal(err)
	}
	FlipByte(t, out, entry)
	return out
}

// FlipByte flips one byte in the middle of entry's data, in place.
func FlipByte(t testing.TB, path, entry string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, idx, err := bundle.Scan(f, nil)
	if err != nil {
		t.Fatal(err)
	}
	loc, ok := idx.Lookup(entry)
	if !ok || loc.Size == 0 {
		t.Fatalf("bundletest: no non-empty entry %q", entry)
	}
	at := loc.Offset + loc.Size/2
	var b [1]byte
	if _, err := f.ReadAt(b[:], at); err != nil {
		t.Fatal(err)
	}
	b[0] ^= 0xff
	if _, err := f.WriteAt(b[:], at); err != nil {
		t.Fatal(err)
	}
}
