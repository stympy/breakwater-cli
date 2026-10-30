package bundle_test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/stympy/breakwater-cli/internal/api"
	"github.com/stympy/breakwater-cli/internal/bundle"
	"github.com/stympy/breakwater-cli/internal/bundle/bundletest"
)

// fixture is one single-manifest image, one 2-platform index, one file and
// one binary.
type fixture struct {
	img     v1.Image
	index   v1.ImageIndex
	opts    bundletest.Options
	restore func() // set by an edit that changes package state
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	img := bundletest.RandomImage(t)
	index := bundletest.PlatformIndex(t, "linux/amd64", "linux/arm64")
	return &fixture{img: img, index: index, opts: bundletest.Options{
		Images: []bundletest.Image{
			{Reference: "registry.breakwaterapp.com/acme/api:2.4.1", Image: img},
			{Kind: "external", Reference: "docker.io/library/redis:7", Index: index},
		},
		Files: []bundletest.File{{Name: "install.sh", Data: []byte("#!/bin/sh\necho hi\n")}},
		Bin:   []bundletest.Bin{{Name: "breakwater_linux_amd64", Platform: "linux/amd64", Data: []byte("ELF...")}},
	}}
}

func readAll(t *testing.T, rc io.ReadCloser, err error) []byte {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRoundTrip(t *testing.T) {
	f := newFixture(t)
	b, err := bundle.Open(bundletest.Build(t, f.opts))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	h := b.Header()
	if h.Format != 1 || h.Platforms != nil || len(h.Images) != 2 || len(h.Files) != 1 || len(h.Bin) != 1 {
		t.Fatalf("header %+v", h)
	}
	if b.Manifest().Product.Slug != "api" {
		t.Fatalf("manifest %+v", b.Manifest())
	}

	layers, _ := f.img.Layers()
	want, _ := layers[0].Compressed()
	wantBytes, _ := io.ReadAll(want)
	digest, _ := layers[0].Digest()
	rc, err := b.Blob(digest.String())
	if got := readAll(t, rc, err); !bytes.Equal(got, wantBytes) {
		t.Fatal("layer bytes differ")
	}
	rawIndex, _ := f.index.RawManifest()
	indexDigest, _ := f.index.Digest()
	rc, err = b.Blob(indexDigest.String())
	if got := readAll(t, rc, err); !bytes.Equal(got, rawIndex) {
		t.Fatal("index bytes differ")
	}
	rc, err = b.File("install.sh")
	if got := readAll(t, rc, err); string(got) != "#!/bin/sh\necho hi\n" {
		t.Fatalf("file %q", got)
	}
	rc, err = b.Bin("breakwater_linux_amd64")
	if got := readAll(t, rc, err); string(got) != "ELF..." {
		t.Fatalf("bin %q", got)
	}
	if _, err := b.File("nope"); err == nil || err.Error() != `the bundle has no file "nope"` {
		t.Fatalf("err %v", err)
	}
	if _, err := b.Blob("sha256:" + strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "the bundle has no blob sha256:000") {
		t.Fatalf("err %v", err)
	}

	imgs := b.Images()
	if len(imgs) != 2 || imgs[0].Platforms != 1 || imgs[1].Platforms != 2 || imgs[0].Size <= 0 || imgs[1].Size <= imgs[0].Size {
		t.Fatalf("images %+v", imgs)
	}
}

func TestPlatformFilteredIndex(t *testing.T) {
	f := newFixture(t)
	im, _ := f.index.IndexManifest()
	f.opts.Platforms = []string{"linux/arm64"}
	f.opts.Images[1].Children = []v1.Hash{im.Manifests[1].Digest}
	b, err := bundle.Open(bundletest.Build(t, f.opts))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if b.Images()[1].Platforms != 1 {
		t.Fatalf("images %+v", b.Images())
	}
	// The dropped child's blobs aren't in the bundle.
	if _, err := b.Blob(im.Manifests[0].Digest.String()); err == nil {
		t.Fatal("dropped child is present")
	}
}

func TestOpenRejectsAFlippedByte(t *testing.T) {
	f := newFixture(t)
	path := bundletest.Build(t, f.opts)
	layers, _ := f.img.Layers()
	d, _ := layers[0].Digest()
	entry := "oci/blobs/sha256/" + d.Hex
	_, err := bundle.Open(bundletest.Corrupt(t, path, entry))
	if err == nil || !strings.Contains(err.Error(), `entry "`+entry+`" doesn't match its sha256`) {
		t.Fatalf("err %v", err)
	}
}

func TestBlobRechecksTheDigestAfterOpen(t *testing.T) {
	f := newFixture(t)
	path := bundletest.Build(t, f.opts)
	b, err := bundle.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	layers, _ := f.img.Layers()
	d, _ := layers[0].Digest()
	// Swap the bytes on disk after Open, as a hostile process might.
	bundletest.FlipByte(t, path, "oci/blobs/sha256/"+d.Hex)
	rc, err := b.Blob(d.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if _, err := io.ReadAll(rc); err == nil || !strings.Contains(err.Error(), "doesn't match its digest") {
		t.Fatalf("err %v", err)
	}
}

func TestOpenRejectsADirectory(t *testing.T) {
	if _, err := bundle.Open(t.TempDir()); err == nil || !strings.Contains(err.Error(), "isn't a regular file") {
		t.Fatalf("err %v", err)
	}
}

func TestValidateFailures(t *testing.T) {
	other := "sha256:" + strings.Repeat("ab", 32)
	cases := []struct {
		name string
		edit func(f *fixture)
		want string
	}{
		{"index child not in the index", func(f *fixture) {
			f.opts.EditHeader = func(h *bundle.Header) { h.Images[1].Children = append(h.Images[1].Children, other) }
		}, "image docker.io/library/redis:7: child " + other + " isn't in its index"},
		{"index child listed twice", func(f *fixture) {
			f.opts.EditHeader = func(h *bundle.Header) { h.Images[1].Children = append(h.Images[1].Children, h.Images[1].Children[0]) }
		}, "lists child sha256:"},
		{"subset of children with platforms null", func(f *fixture) {
			im, _ := f.index.IndexManifest()
			f.opts.Images[1].Children = []v1.Hash{im.Manifests[0].Digest}
		}, "image docker.io/library/redis:7: bundle.json keeps 1 of the index's 2 children, but platforms is all"},
		{"index without children", func(f *fixture) {
			f.opts.EditHeader = func(h *bundle.Header) { h.Images[1].Children = nil }
		}, "image docker.io/library/redis:7: bundle.json lists no children for an index"},
		{"children on a manifest", func(f *fixture) {
			f.opts.EditHeader = func(h *bundle.Header) { h.Images[0].Children = []string{other} }
		}, "image registry.breakwaterapp.com/acme/api:2.4.1: bundle.json lists children for a manifest"},
		{"missing layer", func(f *fixture) {
			layers, _ := f.img.Layers()
			d, _ := layers[0].Digest()
			f.opts.Omit = []string{d.String()}
		}, "image registry.breakwaterapp.com/acme/api:2.4.1: layer sha256:"},
		{"missing config", func(f *fixture) {
			d, _ := f.img.ConfigName()
			f.opts.Omit = []string{d.String()}
		}, "image registry.breakwaterapp.com/acme/api:2.4.1: config "},
		{"missing child", func(f *fixture) {
			im, _ := f.index.IndexManifest()
			f.opts.Omit = []string{im.Manifests[1].Digest.String()}
		}, "image docker.io/library/redis:7: manifest "},
		{"missing top-level blob", func(f *fixture) {
			d, _ := f.img.Digest()
			f.opts.Omit = []string{d.String()}
		}, "image registry.breakwaterapp.com/acme/api:2.4.1: its manifest blob sha256:"},
		{"manifest image not in images", func(f *fixture) {
			f.opts.EditManifest = func(m *api.Manifest) { m.Images[0].Tag = "9.9.9" }
		}, "image registry.breakwaterapp.com/acme/api:2.4.1 (tag 9.9.9) is in the manifest but not in bundle.json"},
		{"images entry not in the manifest", func(f *fixture) {
			f.opts.EditManifest = func(m *api.Manifest) { m.Images = m.Images[:1] }
		}, "image docker.io/library/redis:7 is in bundle.json but not in the manifest"},
		{"manifest size differs", func(f *fixture) {
			f.opts.EditManifest = func(m *api.Manifest) { m.Images[0].Size++ }
		}, "image registry.breakwaterapp.com/acme/api:2.4.1: its manifest blob is "},
		{"media type differs", func(f *fixture) {
			f.opts.EditHeader = func(h *bundle.Header) { h.Images[0].MediaType = "application/vnd.oci.image.manifest.v1+json" }
		}, "image registry.breakwaterapp.com/acme/api:2.4.1: media type application/vnd.oci.image.manifest.v1+json in bundle.json doesn't match the manifest's"},
		{"file sha differs from the manifest", func(f *fixture) {
			f.opts.EditManifest = func(m *api.Manifest) { m.Files[0].SHA256 = strings.Repeat("cd", 32) }
		}, "file install.sh: bundle.json's size or sha256 doesn't match the manifest"},
		{"file in manifest only", func(f *fixture) {
			f.opts.EditHeader = func(h *bundle.Header) { h.Files = nil }
		}, "file install.sh is in the manifest but not in bundle.json"},
		{"file not in the bundle", func(f *fixture) {
			f.opts.Omit = []string{"files/install.sh"}
		}, `file install.sh: entry "files/install.sh" is missing`},
		{"bin sha differs", func(f *fixture) {
			f.opts.EditHeader = func(h *bundle.Header) { h.Bin[0].SHA256 = strings.Repeat("cd", 32) }
		}, `binary breakwater_linux_amd64: entry "bin/breakwater_linux_amd64" doesn't match its size or sha256`},
		{"bad bin name", func(f *fixture) {
			f.opts.EditHeader = func(h *bundle.Header) { h.Bin[0].Name = "../x" }
		}, `binary "../x" has an unsafe name`},
		{"unreferenced entry", func(f *fixture) {
			f.opts.Extra = map[string][]byte{"files/stray.txt": []byte("stray")}
		}, `entry "files/stray.txt" isn't referenced by any image, file or binary`},
		{"manifest doesn't parse", func(f *fixture) {
			f.opts.EditHeader = func(h *bundle.Header) { h.Manifest = []byte(`[]`) }
		}, "bundle.json's manifest doesn't parse"},
		{"manifest invalid", func(f *fixture) {
			f.opts.EditManifest = func(m *api.Manifest) { m.Images[0].Kind = "weird" }
		}, `bundle.json's manifest: manifest image 1 has unknown kind "weird"`},
		{"child outside the platforms", func(f *fixture) {
			im, _ := f.index.IndexManifest()
			f.opts.Platforms = []string{"linux/amd64"}
			f.opts.Images[1].Children = []v1.Hash{im.Manifests[1].Digest}
		}, "image docker.io/library/redis:7: child sha256:"},
		{"repository_path differs", func(f *fixture) {
			f.opts.EditManifest = func(m *api.Manifest) { m.Images[0].RepositoryPath = "acme/other" }
		}, "image registry.breakwaterapp.com/acme/api:2.4.1 is in the manifest but not in bundle.json"},
		{"index.json extra annotation", func(f *fixture) {
			f.opts.EditIndexJSON = func(im *v1.IndexManifest) { im.Manifests[0].Annotations["x"] = "y" }
		}, "oci/index.json: the entry for sha256:"},
		{"index.json containerd name differs", func(f *fixture) {
			f.opts.EditIndexJSON = func(im *v1.IndexManifest) {
				im.Manifests[1].Annotations["io.containerd.image.name"] = "docker.io/library/evil:1"
			}
		}, "must have exactly the annotations"},
		{"index.json ref name differs", func(f *fixture) {
			f.opts.EditIndexJSON = func(im *v1.IndexManifest) {
				im.Manifests[1].Annotations = bundle.IndexAnnotations("docker.io/library/evil:1")
			}
		}, "oci/index.json doesn't list exactly the bundle's images"},
		{"bin name with an escape", func(f *fixture) {
			f.opts.EditHeader = func(h *bundle.Header) { h.Bin[0].Name = "x\x1b[31m" }
		}, `binary "x\x1b[31m" has an unsafe name`},
		{"bin platform invalid", func(f *fixture) {
			f.opts.EditHeader = func(h *bundle.Header) { h.Bin[0].Platform = "Linux/AMD64" }
		}, `binary breakwater_linux_amd64 has an invalid platform "Linux/AMD64"`},
		{"cli_version invalid", func(f *fixture) {
			f.opts.EditHeader = func(h *bundle.Header) { h.CLIVersion = "1.0\x1b]0;pwned\x07" }
		}, `bundle.json has an invalid cli_version`},
		{"nested index lists a child twice", func(f *fixture) {
			img := bundletest.RandomImage(t)
			inner := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: img}, mutate.IndexAddendum{Add: img})
			f.opts.Images[1].Index = mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: inner})
		}, "image docker.io/library/redis:7: index sha256:"},
		{"descriptor budget", func(f *fixture) {
			f.restore = bundle.SetMaxDescriptors(5)
		}, "the bundle's images have more than 5 descriptors"},
		{"index.json disagrees", func(f *fixture) {
			f.opts.EditIndexJSON = func(im *v1.IndexManifest) { im.Manifests = im.Manifests[:1] }
		}, "oci/index.json doesn't list exactly the bundle's images"},
		{"index.json missing", func(f *fixture) {
			f.opts.Omit = []string{"oci/index.json"}
		}, `entry "oci/index.json" is missing`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			c.edit(f)
			if f.restore != nil {
				defer f.restore()
			}
			b, err := bundle.Open(bundletest.Build(t, f.opts))
			if err == nil {
				b.Close()
				t.Fatalf("accepted; want %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q; want it to contain %q", err, c.want)
			}
		})
	}
}

// TestRepeatedIndexesAreValidatedOnce: many images naming one index, which
// nests an index, stay within a small descriptor budget because walks are
// memoized; each visit is still counted.
func TestRepeatedIndexesAreValidatedOnce(t *testing.T) {
	inner := bundletest.PlatformIndex(t, "linux/amd64", "linux/arm64")
	outer := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: inner}, mutate.IndexAddendum{Add: bundletest.RandomImage(t)})
	var opts bundletest.Options
	for i := range 50 {
		opts.Images = append(opts.Images, bundletest.Image{Kind: "external", Reference: fmt.Sprintf("docker.io/library/app%d:1", i), Index: outer})
	}
	readFor := func(n int) int64 {
		o := opts
		o.Images = opts.Images[:n]
		f, err := os.Open(bundletest.Build(t, o))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		h, idx, err := bundle.Scan(f, nil)
		if err != nil {
			t.Fatal(err)
		}
		ra := &countingReaderAt{r: f}
		if _, err := bundle.Validate(h, idx, ra); err != nil {
			t.Fatal(err)
		}
		return ra.n
	}
	one, fifty := readFor(1), readFor(50)
	// Only oci/index.json grows (about 200 bytes an image); manifests and
	// indexes are read once.
	if fifty > one+50*300 {
		t.Fatalf("Validate read %d bytes for 50 images, %d for 1", fifty, one)
	}
	t.Cleanup(bundle.SetMaxDescriptors(100))
	if _, err := bundle.Open(bundletest.Build(t, opts)); err == nil || !strings.Contains(err.Error(), "more than 100 descriptors") {
		t.Fatalf("err %v", err)
	}
}

type countingReaderAt struct {
	r io.ReaderAt
	n int64
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.r.ReadAt(p, off)
	c.n += int64(n)
	return n, err
}

func TestBlobCloseReportsAMismatchAfterAnExactRead(t *testing.T) {
	f := newFixture(t)
	path := bundletest.Build(t, f.opts)
	b, err := bundle.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	layers, _ := f.img.Layers()
	d, _ := layers[0].Digest()
	entry := "oci/blobs/sha256/" + d.Hex
	loc, _ := b.Index().Lookup(entry)
	bundletest.FlipByte(t, path, entry)
	rc, err := b.Blob(d.String())
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, loc.Size)
	io.ReadFull(rc, buf) // ReadFull drops an error that comes with the last byte
	if _, err := rc.Read(make([]byte, 1)); err == nil || err == io.EOF {
		t.Fatalf("next Read err %v", err)
	}
	if err := rc.Close(); err == nil || !strings.Contains(err.Error(), "doesn't match its digest") {
		t.Fatalf("Close err %v", err)
	}
}

func TestOpenLeavesNoFileOpenOnFailure(t *testing.T) {
	f := newFixture(t)
	f.opts.Omit = []string{"files/install.sh"}
	path := bundletest.Build(t, f.opts)
	if _, err := bundle.Open(path); err == nil {
		t.Fatal("accepted")
	}
	if err := os.Remove(path); err != nil { // would fail on Windows with a handle open
		t.Fatal(err)
	}
}
