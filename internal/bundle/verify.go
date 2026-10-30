package bundle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stympy/breakwater-cli/internal/api"
)

var (
	platformPattern   = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9]+(/[a-z0-9]+)?$`)
	cliVersionPattern = regexp.MustCompile(`^[A-Za-z0-9.+-]{1,32}$`)
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
	v := &validator{
		h: h, idx: idx, ra: ra,
		used:    make(map[string]bool, len(idx.Entries)),
		walks:   map[walkKey]walkResult{},
		indexes: map[v1.Hash]*v1.IndexManifest{},
	}
	return v.run()
}

// maxDescriptors caps the descriptors Validate walks across all images
// (top-level images, children, configs and layers, counting repeats).
var maxDescriptors = 100000

type validator struct {
	h       *Header
	idx     *Index
	ra      io.ReaderAt
	used    map[string]bool
	walks   map[walkKey]walkResult
	indexes map[v1.Hash]*v1.IndexManifest
	walked  int
}

type imageKey struct{ kind, reference, tag, repositoryPath, digest string }

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
		if !platformPattern.MatchString(p) {
			return nil, fmt.Errorf("bundle.json lists an invalid platform %q", p)
		}
	}
	if _, err := time.Parse(time.RFC3339, v.h.CreatedAt); err != nil {
		return nil, fmt.Errorf("bundle.json has an invalid created_at %q", v.h.CreatedAt)
	}
	if !cliVersionPattern.MatchString(v.h.CLIVersion) {
		return nil, fmt.Errorf("bundle.json has an invalid cli_version %q", v.h.CLIVersion)
	}

	byKey, err := v.matchImages(&m)
	if err != nil {
		return nil, err
	}
	sum := &Summary{Manifest: &m}
	for _, img := range v.h.Images {
		info, err := v.image(img, byKey[imageKey{img.Kind, img.Reference, img.Tag, img.RepositoryPath, img.Digest}])
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
		inHeader[imageKey{img.Kind, img.Reference, img.Tag, img.RepositoryPath, img.Digest}]++
	}
	inManifest := map[imageKey]int{}
	for _, mi := range m.Images {
		k := imageKey{mi.Kind, mi.Reference, mi.Tag, mi.RepositoryPath, mi.Digest}
		byKey[k] = mi
		inManifest[k]++
		if inManifest[k] > inHeader[k] {
			return nil, fmt.Errorf("image %s is in the manifest but not in bundle.json", describe(mi.Reference, mi.Tag))
		}
	}
	for _, img := range v.h.Images {
		k := imageKey{img.Kind, img.Reference, img.Tag, img.RepositoryPath, img.Digest}
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

func (s *sizer) add(es ...IndexEntry) {
	for _, e := range es {
		if !s.seen[e.Path] {
			s.seen[e.Path] = true
			s.total += e.Size
		}
	}
}

// count charges one descriptor against the walk budget.
func (v *validator) count() error {
	v.walked++
	if v.walked > maxDescriptors {
		return fmt.Errorf("the bundle's images have more than %d descriptors", maxDescriptors)
	}
	return nil
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
	if err := v.count(); err != nil {
		return info, err
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
		blobs, err := v.walk("manifest", top, false)
		if err != nil {
			return info, err
		}
		sz.add(blobs...)
		info.Size = sz.total
		return info, nil
	}

	im, err := v.index(top, e)
	if err != nil {
		return info, err
	}
	descs := make(map[v1.Hash]v1.Descriptor, len(im.Manifests))
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
		if !IsAttestation(d) && v.h.Platforms != nil {
			if !PlatformMatches(d.Platform, v.h.Platforms) {
				p := PlatformString(d.Platform)
				if p == "" {
					p = "no platform"
				}
				return info, fmt.Errorf("child %s is for %s, which isn't one of the bundle's platforms", c, p)
			}
		}
		blobs, err := v.walk(childWhat(d), d, true)
		if err != nil {
			return info, err
		}
		sz.add(blobs...)
		if !IsAttestation(d) {
			info.Platforms++
		}
	}
	if v.h.Platforms == nil && len(kept) != len(descs) {
		return info, fmt.Errorf("bundle.json keeps %d of the index's %d children, but platforms is all", len(kept), len(descs))
	}
	info.Size = sz.total
	return info, nil
}

func childWhat(d v1.Descriptor) string {
	if d.MediaType.IsIndex() {
		return "index"
	}
	return "manifest"
}

// PlatformString is "os/arch[/variant]", or "" for no platform.
func PlatformString(p *v1.Platform) string {
	if p == nil {
		return ""
	}
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

// PlatformMatches reports whether p matches one of the requested platforms:
// OS and architecture must be equal, and the variant too when the request
// names one ("linux/arm64" matches linux/arm64/v8; "linux/arm/v7" doesn't
// match linux/arm/v6).
func PlatformMatches(p *v1.Platform, wanted []string) bool {
	if p == nil {
		return false
	}
	for _, w := range wanted {
		parts := strings.Split(w, "/")
		if len(parts) < 2 || parts[0] != p.OS || parts[1] != p.Architecture {
			continue
		}
		if len(parts) == 2 || parts[2] == p.Variant {
			return true
		}
	}
	return false
}

// IsAttestation reports whether an index child is a buildx attestation
// manifest (by annotation, or the unknown/unknown platform).
func IsAttestation(d v1.Descriptor) bool {
	if d.Annotations[referenceTypeAnnotation] == "attestation-manifest" {
		return true
	}
	return d.Platform != nil && d.Platform.OS == "unknown" && d.Platform.Architecture == "unknown"
}

type walkResult struct {
	blobs     []IndexEntry
	mediaType types.MediaType
}

type walkKey struct {
	digest   v1.Hash
	nestedOK bool
}

// walk validates a descriptor's manifest or index (nestedOK allows an
// index, whose children are then all required and must be manifests) and
// returns every blob under it, its own included. Results are memoized by
// digest, so a hostile bundle can't make Validate re-read the same blobs
// over and over; every visit still counts against maxDescriptors.
func (v *validator) walk(what string, d v1.Descriptor, nestedOK bool) ([]IndexEntry, error) {
	if err := v.count(); err != nil {
		return nil, err
	}
	key := walkKey{d.Digest, nestedOK}
	if r, ok := v.walks[key]; ok {
		// The subtree was checked; this descriptor of it still must be right.
		if _, err := v.blob(what, d); err != nil {
			return nil, err
		}
		if d.MediaType != r.mediaType {
			return nil, fmt.Errorf("%s %s has media type %s here but %s elsewhere", what, d.Digest, d.MediaType, r.mediaType)
		}
		return r.blobs, nil
	}
	var blobs []IndexEntry
	switch {
	case d.MediaType.IsImage():
		e, err := v.blob(what, d)
		if err != nil {
			return nil, err
		}
		under, err := v.manifest(d, e)
		if err != nil {
			return nil, err
		}
		blobs = append([]IndexEntry{e}, under...)
	case d.MediaType.IsIndex() && nestedOK:
		e, err := v.blob(what, d)
		if err != nil {
			return nil, err
		}
		im, err := v.index(d, e)
		if err != nil {
			return nil, err
		}
		blobs = []IndexEntry{e}
		for _, c := range im.Manifests {
			under, err := v.walk(childWhat(c), c, false)
			if err != nil {
				return nil, err
			}
			blobs = append(blobs, under...)
		}
	case d.MediaType.IsIndex():
		return nil, fmt.Errorf("index %s is nested more than one level deep", d.Digest)
	default:
		return nil, fmt.Errorf("child %s has unsupported media type %s", d.Digest, d.MediaType)
	}
	v.walks[key] = walkResult{blobs: blobs, mediaType: d.MediaType}
	return blobs, nil
}

// index reads and parses an index blob, memoized by digest. An index that
// lists a digest twice is refused.
func (v *validator) index(d v1.Descriptor, e IndexEntry) (*v1.IndexManifest, error) {
	if im, ok := v.indexes[d.Digest]; ok {
		if im.MediaType != "" && im.MediaType != d.MediaType {
			return nil, fmt.Errorf("index %s says media type %s, but its descriptor says %s", d.Digest, im.MediaType, d.MediaType)
		}
		return im, nil
	}
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
	seen := make(map[v1.Hash]bool, len(im.Manifests))
	for _, c := range im.Manifests {
		if seen[c.Digest] {
			return nil, fmt.Errorf("index %s lists %s twice", d.Digest, c.Digest)
		}
		seen[c.Digest] = true
	}
	v.indexes[d.Digest] = im
	return im, nil
}

// manifest checks a manifest's config and layers, returning their blobs.
func (v *validator) manifest(d v1.Descriptor, e IndexEntry) ([]IndexEntry, error) {
	raw, err := readSmall(v.ra, e, MaxManifestSize)
	if err != nil {
		return nil, err
	}
	m, err := v1.ParseManifest(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("manifest %s doesn't parse: %w", d.Digest, err)
	}
	if m.MediaType != "" && m.MediaType != d.MediaType {
		return nil, fmt.Errorf("manifest %s says media type %s, but its descriptor says %s", d.Digest, m.MediaType, d.MediaType)
	}
	if err := v.count(); err != nil {
		return nil, err
	}
	ce, err := v.blob("config", m.Config)
	if err != nil {
		return nil, err
	}
	blobs := []IndexEntry{ce}
	for _, l := range m.Layers {
		if err := v.count(); err != nil {
			return nil, err
		}
		le, err := v.blob("layer", l)
		if err != nil {
			return nil, err
		}
		blobs = append(blobs, le)
	}
	return blobs, nil
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
		if !api.ValidFileName(b.Name) {
			return fmt.Errorf("binary %q has an unsafe name", b.Name)
		}
		if !platformPattern.MatchString(b.Platform) {
			return fmt.Errorf("binary %s has an invalid platform %q", b.Name, b.Platform)
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
		name := d.Annotations[refNameAnnotation]
		if len(d.Annotations) != 2 || name == "" || d.Annotations[containerdNameAnnotation] != name {
			return fmt.Errorf("%s: the entry for %s must have exactly the annotations %s and %s, both its reference", IndexPath, d.Digest, refNameAnnotation, containerdNameAnnotation)
		}
		got = append(got, row{d.Digest.String(), string(d.MediaType), name, d.Size})
	}
	for _, img := range v.h.Images {
		mi := byKey[imageKey{img.Kind, img.Reference, img.Tag, img.RepositoryPath, img.Digest}]
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

// ValidPlatform reports whether s is "os/arch" or "os/arch/variant" in
// lowercase letters and digits, as bundle.json and the API require.
func ValidPlatform(s string) bool { return platformPattern.MatchString(s) }
