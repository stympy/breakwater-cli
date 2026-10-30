package bundle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stympy/breakwater-cli/internal/api"
)

const (
	refNameAnnotation        = "org.opencontainers.image.ref.name"
	containerdNameAnnotation = "io.containerd.image.name"
	referenceTypeAnnotation  = "vnd.docker.reference.type"
)

// ImageInfo summarizes one image of a validated bundle.
type ImageInfo struct {
	Reference string
	Digest    string
	MediaType string
	Platforms int   // platform manifests kept, not counting attestations
	Size      int64 // bytes of the image's distinct blobs in the bundle
}

// Summary is what Validate learned about a bundle.
type Summary struct {
	Manifest *api.Manifest
	Images   []ImageInfo
}

// IndexAnnotations are the annotations of an image's descriptor in
// oci/index.json.
func IndexAnnotations(reference string) map[string]string {
	return map[string]string{refNameAnnotation: reference, containerdNameAnnotation: reference}
}

// Validate checks a scanned bundle's structure: bundle.json agrees with its
// release manifest, every image's manifests, configs and layers are present
// at their descriptors' sizes, files and binaries match, the OCI layout is
// there and lists exactly the bundle's images, and nothing else is. ra reads
// the bundle at the offsets in idx; small blobs it reads are re-checked
// against their digests.
func Validate(h *Header, idx *Index, ra io.ReaderAt) (*Summary, error) {
	v := &validator{h: h, idx: idx, ra: ra, used: make(map[string]bool, len(idx.Entries))}
	return v.run()
}

type validator struct {
	h    *Header
	idx  *Index
	ra   io.ReaderAt
	used map[string]bool
}

type imageKey struct{ kind, reference, tag, digest string }

func describe(reference, tag string) string {
	if tag != "" && !strings.HasSuffix(reference, ":"+tag) {
		return fmt.Sprintf("%s (tag %s)", reference, tag)
	}
	return reference
}

func (v *validator) run() (*Summary, error) {
	var m api.Manifest
	if err := json.Unmarshal(v.h.Manifest, &m); err != nil {
		return nil, fmt.Errorf("bundle.json's manifest doesn't parse: %w", err)
	}
	if err := api.ValidateManifest(&m); err != nil {
		return nil, fmt.Errorf("bundle.json's manifest: %w", err)
	}
	if v.h.Platforms != nil && len(v.h.Platforms) == 0 {
		return nil, fmt.Errorf("bundle.json lists no platforms (null means all)")
	}
	for _, p := range v.h.Platforms {
		if _, err := v1.ParsePlatform(p); err != nil || p == "" {
			return nil, fmt.Errorf("bundle.json lists an invalid platform %q", p)
		}
	}

	byKey, err := v.matchImages(&m)
	if err != nil {
		return nil, err
	}
	sum := &Summary{Manifest: &m}
	for _, img := range v.h.Images {
		info, err := v.image(img, byKey[imageKey{img.Kind, img.Reference, img.Tag, img.Digest}])
		if err != nil {
			return nil, fmt.Errorf("image %s: %w", describe(img.Reference, img.Tag), err)
		}
		sum.Images = append(sum.Images, info)
	}
	if err := v.files(&m); err != nil {
		return nil, err
	}
	if err := v.bins(); err != nil {
		return nil, err
	}
	if err := v.layout(byKey); err != nil {
		return nil, err
	}
	for _, e := range v.idx.Entries {
		if !v.used[e.Path] {
			return nil, fmt.Errorf("entry %q isn't referenced by any image, file or binary", e.Path)
		}
	}
	return sum, nil
}

// matchImages checks that the manifest's images and bundle.json's are the
// same (as multisets), and maps each to its manifest entry.
func (v *validator) matchImages(m *api.Manifest) (map[imageKey]api.ManifestImage, error) {
	byKey := map[imageKey]api.ManifestImage{}
	inHeader := map[imageKey]int{}
	for _, img := range v.h.Images {
		inHeader[imageKey{img.Kind, img.Reference, img.Tag, img.Digest}]++
	}
	inManifest := map[imageKey]int{}
	for _, mi := range m.Images {
		k := imageKey{mi.Kind, mi.Reference, mi.Tag, mi.Digest}
		byKey[k] = mi
		inManifest[k]++
		if inManifest[k] > inHeader[k] {
			return nil, fmt.Errorf("image %s is in the manifest but not in bundle.json", describe(mi.Reference, mi.Tag))
		}
	}
	for _, img := range v.h.Images {
		k := imageKey{img.Kind, img.Reference, img.Tag, img.Digest}
		if inHeader[k] > inManifest[k] {
			return nil, fmt.Errorf("image %s is in bundle.json but not in the manifest", describe(img.Reference, img.Tag))
		}
	}
	return byKey, nil
}

// need marks an entry used and checks it's present at size (size < 0: any).
func (v *validator) need(path string, size int64) (IndexEntry, error) {
	e, ok := v.idx.entry(path)
	if !ok {
		return e, fmt.Errorf("entry %q is missing", path)
	}
	v.used[path] = true
	if size >= 0 && e.Size != size {
		return e, fmt.Errorf("entry %q is %d bytes, but its descriptor says %d", path, e.Size, size)
	}
	return e, nil
}

// blob finds a descriptor's blob; what names it in errors ("layer", ...).
func (v *validator) blob(what string, d v1.Descriptor) (IndexEntry, error) {
	path, err := BlobPath(d.Digest.String())
	if err != nil {
		return IndexEntry{}, fmt.Errorf("%s has an %w", what, err)
	}
	e, ok := v.idx.entry(path)
	if !ok {
		return e, fmt.Errorf("%s %s is missing", what, d.Digest)
	}
	v.used[path] = true
	if e.Size != d.Size {
		return e, fmt.Errorf("%s %s is %d bytes, but its descriptor says %d", what, d.Digest, e.Size, d.Size)
	}
	return e, nil
}

// sizer adds up an image's distinct blobs.
type sizer struct {
	seen  map[string]bool
	total int64
}

func (s *sizer) add(e IndexEntry) {
	if !s.seen[e.Path] {
		s.seen[e.Path] = true
		s.total += e.Size
	}
}

func (v *validator) image(img Image, mi api.ManifestImage) (ImageInfo, error) {
	info := ImageInfo{Reference: img.Reference, Digest: img.Digest, MediaType: img.MediaType}
	if img.MediaType != mi.MediaType {
		return info, fmt.Errorf("media type %s in bundle.json doesn't match the manifest's %s", img.MediaType, mi.MediaType)
	}
	mt := types.MediaType(img.MediaType)
	switch {
	case mt.IsIndex():
		if len(img.Children) == 0 {
			return info, fmt.Errorf("bundle.json lists no children for an index")
		}
	case mt.IsImage():
		if len(img.Children) > 0 {
			return info, fmt.Errorf("bundle.json lists children for a manifest")
		}
	default:
		return info, fmt.Errorf("unsupported media type %s", mt)
	}
	hash, err := v1.NewHash(img.Digest)
	if err != nil {
		return info, err
	}
	top := v1.Descriptor{MediaType: mt, Digest: hash, Size: mi.Size}
	path, err := BlobPath(img.Digest)
	if err != nil {
		return info, err
	}
	e, ok := v.idx.entry(path)
	if !ok {
		return info, fmt.Errorf("its manifest blob %s is missing", img.Digest)
	}
	v.used[path] = true
	if e.Size != mi.Size {
		return info, fmt.Errorf("its manifest blob is %d bytes, but the manifest says %d", e.Size, mi.Size)
	}
	sz := &sizer{seen: map[string]bool{}}
	sz.add(e)

	if mt.IsImage() {
		info.Platforms = 1
		if err := v.manifest(top, e, sz); err != nil {
			return info, err
		}
		info.Size = sz.total
		return info, nil
	}

	im, err := v.index(top, e)
	if err != nil {
		return info, err
	}
	descs := map[v1.Hash]v1.Descriptor{}
	for _, d := range im.Manifests {
		descs[d.Digest] = d
	}
	kept := map[string]bool{}
	for _, c := range img.Children {
		if kept[c] {
			return info, fmt.Errorf("bundle.json lists child %s twice", c)
		}
		kept[c] = true
		ch, err := v1.NewHash(c)
		if err != nil {
			return info, fmt.Errorf("child %s isn't in its index", c)
		}
		d, ok := descs[ch]
		if !ok {
			return info, fmt.Errorf("child %s isn't in its index", c)
		}
		if err := v.child(d, true, sz); err != nil {
			return info, err
		}
		if !isAttestation(d) {
			info.Platforms++
		}
	}
	if v.h.Platforms == nil && len(kept) != len(descs) {
		return info, fmt.Errorf("bundle.json keeps %d of the index's %d children, but platforms is all", len(kept), len(descs))
	}
	info.Size = sz.total
	return info, nil
}

func isAttestation(d v1.Descriptor) bool {
	if d.Annotations[referenceTypeAnnotation] == "attestation-manifest" {
		return true
	}
	return d.Platform != nil && d.Platform.OS == "unknown" && d.Platform.Architecture == "unknown"
}

// child validates an index's child manifest; nestedOK allows it to be an
// index itself, whose children are then all required.
func (v *validator) child(d v1.Descriptor, nestedOK bool, sz *sizer) error {
	switch {
	case d.MediaType.IsImage():
		e, err := v.blob("manifest", d)
		if err != nil {
			return err
		}
		sz.add(e)
		return v.manifest(d, e, sz)
	case d.MediaType.IsIndex() && nestedOK:
		e, err := v.blob("index", d)
		if err != nil {
			return err
		}
		sz.add(e)
		im, err := v.index(d, e)
		if err != nil {
			return err
		}
		for _, c := range im.Manifests {
			if err := v.child(c, false, sz); err != nil {
				return err
			}
		}
		return nil
	case d.MediaType.IsIndex():
		return fmt.Errorf("index %s is nested more than one level deep", d.Digest)
	default:
		return fmt.Errorf("child %s has unsupported media type %s", d.Digest, d.MediaType)
	}
}

func (v *validator) index(d v1.Descriptor, e IndexEntry) (*v1.IndexManifest, error) {
	raw, err := readSmall(v.ra, e, MaxManifestSize)
	if err != nil {
		return nil, err
	}
	im, err := v1.ParseIndexManifest(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("index %s doesn't parse: %w", d.Digest, err)
	}
	if im.MediaType != "" && im.MediaType != d.MediaType {
		return nil, fmt.Errorf("index %s says media type %s, but its descriptor says %s", d.Digest, im.MediaType, d.MediaType)
	}
	return im, nil
}

func (v *validator) manifest(d v1.Descriptor, e IndexEntry, sz *sizer) error {
	raw, err := readSmall(v.ra, e, MaxManifestSize)
	if err != nil {
		return err
	}
	m, err := v1.ParseManifest(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("manifest %s doesn't parse: %w", d.Digest, err)
	}
	if m.MediaType != "" && m.MediaType != d.MediaType {
		return fmt.Errorf("manifest %s says media type %s, but its descriptor says %s", d.Digest, m.MediaType, d.MediaType)
	}
	ce, err := v.blob("config", m.Config)
	if err != nil {
		return err
	}
	sz.add(ce)
	for _, l := range m.Layers {
		le, err := v.blob("layer", l)
		if err != nil {
			return err
		}
		sz.add(le)
	}
	return nil
}

func (v *validator) files(m *api.Manifest) error {
	inHeader := map[string]File{}
	for _, f := range v.h.Files {
		if !validName(f.Name) {
			return fmt.Errorf("file %q has an unsafe name", f.Name)
		}
		if _, dup := inHeader[f.Name]; dup {
			return fmt.Errorf("bundle.json lists file %s twice", f.Name)
		}
		inHeader[f.Name] = f
	}
	inManifest := map[string]bool{}
	for _, mf := range m.Files {
		inManifest[mf.Name] = true
		f, ok := inHeader[mf.Name]
		if !ok {
			return fmt.Errorf("file %s is in the manifest but not in bundle.json", mf.Name)
		}
		if f.Size != mf.Size || f.SHA256 != mf.SHA256 {
			return fmt.Errorf("file %s: bundle.json's size or sha256 doesn't match the manifest", mf.Name)
		}
	}
	for _, f := range v.h.Files {
		if !inManifest[f.Name] {
			return fmt.Errorf("file %s is in bundle.json but not in the manifest", f.Name)
		}
		e, err := v.need(FilePath(f.Name), -1)
		if err != nil {
			return fmt.Errorf("file %s: %w", f.Name, err)
		}
		if e.Size != f.Size || e.SHA256 != f.SHA256 {
			return fmt.Errorf("file %s: entry %q doesn't match its size or sha256", f.Name, e.Path)
		}
	}
	return nil
}

func (v *validator) bins() error {
	seen := map[string]bool{}
	for _, b := range v.h.Bin {
		if !validName(b.Name) {
			return fmt.Errorf("binary %q has an unsafe name", b.Name)
		}
		if seen[b.Name] {
			return fmt.Errorf("bundle.json lists binary %s twice", b.Name)
		}
		seen[b.Name] = true
		e, err := v.need(BinPath(b.Name), -1)
		if err != nil {
			return fmt.Errorf("binary %s: %w", b.Name, err)
		}
		if e.Size != b.Size || e.SHA256 != b.SHA256 {
			return fmt.Errorf("binary %s: entry %q doesn't match its size or sha256", b.Name, e.Path)
		}
	}
	return nil
}

// layout checks oci/oci-layout and that oci/index.json lists exactly the
// bundle's images, named by reference.
func (v *validator) layout(byKey map[imageKey]api.ManifestImage) error {
	e, err := v.need(LayoutPath, -1)
	if err != nil {
		return err
	}
	raw, err := readSmall(v.ra, e, MaxManifestSize)
	if err != nil {
		return err
	}
	var layout struct {
		ImageLayoutVersion string `json:"imageLayoutVersion"`
	}
	if json.Unmarshal(raw, &layout) != nil || layout.ImageLayoutVersion != "1.0.0" {
		return fmt.Errorf("%s isn't a version 1.0.0 OCI image layout", LayoutPath)
	}

	e, err = v.need(IndexPath, -1)
	if err != nil {
		return err
	}
	raw, err = readSmall(v.ra, e, MaxManifestSize)
	if err != nil {
		return err
	}
	im, err := v1.ParseIndexManifest(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("%s doesn't parse: %w", IndexPath, err)
	}
	type row struct {
		digest, mediaType, name string
		size                    int64
	}
	var got, want []row
	for _, d := range im.Manifests {
		got = append(got, row{d.Digest.String(), string(d.MediaType), d.Annotations[refNameAnnotation], d.Size})
	}
	for _, img := range v.h.Images {
		mi := byKey[imageKey{img.Kind, img.Reference, img.Tag, img.Digest}]
		want = append(want, row{img.Digest, img.MediaType, img.Reference, mi.Size})
	}
	cmp := func(a, b row) int { return strings.Compare(a.digest+" "+a.name, b.digest+" "+b.name) }
	slices.SortFunc(got, cmp)
	slices.SortFunc(want, cmp)
	if !slices.Equal(got, want) {
		return fmt.Errorf("%s doesn't list exactly the bundle's images", IndexPath)
	}
	return nil
}
