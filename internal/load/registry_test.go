package load

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stympy/breakwater-cli/internal/bundle"
	"github.com/stympy/breakwater-cli/internal/bundle/bundletest"
)

const zarfConfig = "application/vnd.zarf.config.v1+json"

func TestTargetName(t *testing.T) {
	internal := bundle.Image{Kind: "internal", Reference: "registry.breakwaterapp.com/acme/api:2.4.1", RepositoryPath: "acme/api", Tag: "2.4.1"}
	ext := func(ref string) bundle.Image { return bundle.Image{Kind: "external", Reference: ref} }
	for _, tc := range []struct {
		name     string
		img      bundle.Image
		registry string
		want     string
	}{
		{"internal", internal, "reg.example.com", "reg.example.com/acme/api:2.4.1"},
		{"docker hub, full", ext("docker.io/library/postgres:16.4"), "reg.example.com", "reg.example.com/docker.io/library/postgres:16.4"},
		{"docker hub, short", ext("postgres:16.4"), "reg.example.com", "reg.example.com/docker.io/library/postgres:16.4"},
		{"docker hub, no tag", ext("busybox"), "reg.example.com", "reg.example.com/docker.io/library/busybox:latest"},
		{"ghcr", ext("ghcr.io/org/x:1"), "reg.example.com", "reg.example.com/ghcr.io/org/x:1"},
		{"prefix", internal, "reg.example.com/mirror/acme", "reg.example.com/mirror/acme/acme/api:2.4.1"},
		{"port", ext("redis:7"), "localhost:5000", "localhost:5000/docker.io/library/redis:7"},
		{"port and prefix", internal, "10.0.0.5:5000/bw", "10.0.0.5:5000/bw/acme/api:2.4.1"},
		{"external on a host with a port", ext("localhost:6000/x:1"), "reg.example.com", "reg.example.com/localhost_6000/x:1"},
		{"external on an IP and port", ext("10.1.2.3:443/team/x"), "reg.example.com/m", "reg.example.com/m/10.1.2.3_443/team/x:latest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := TargetName(tc.img, tc.registry)
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if _, err := name.ParseReference(got); err != nil {
				t.Fatalf("%q doesn't parse: %v", got, err)
			}
		})
	}
}

func TestPlanTargets(t *testing.T) {
	imgs := []bundle.Image{
		{Kind: "internal", Reference: "registry.breakwaterapp.com/acme/api:2.4.1", RepositoryPath: "acme/api", Tag: "2.4.1"},
		{Kind: "external", Reference: "redis:7"},
	}
	for _, tc := range []struct{ registry, host, first string }{
		{"docker.io/mirror", "index.docker.io", "index.docker.io/mirror/acme/api:2.4.1"},
		{"docker.io", "index.docker.io", "index.docker.io/acme/api:2.4.1"},
		{"reg.example.com:5000/m", "reg.example.com:5000", "reg.example.com:5000/m/acme/api:2.4.1"},
	} {
		host, targets, err := planTargets(imgs, tc.registry, false)
		if err != nil {
			t.Fatalf("%s: %v", tc.registry, err)
		}
		if host != tc.host || len(targets) != 2 || targets[0].tag.Name() != tc.first {
			t.Fatalf("%s: host %q, targets %+v", tc.registry, host, targets)
		}
	}
}

// testRegistry is an in-memory registry that counts requests.
func testRegistry(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	reg := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		reg.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://"), &n
}

func openBundle(t *testing.T, opts bundletest.Options) (*bundle.Bundle, string) {
	t.Helper()
	path := bundletest.Build(t, opts)
	b, err := bundle.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b, path
}

func digestOf(t *testing.T, x interface{ Digest() (v1.Hash, error) }) v1.Hash {
	t.Helper()
	d, err := x.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func childDigests(t *testing.T, idx v1.ImageIndex) []v1.Hash {
	t.Helper()
	im, err := idx.IndexManifest()
	if err != nil {
		t.Fatal(err)
	}
	var out []v1.Hash
	for _, d := range im.Manifests {
		out = append(out, d.Digest)
	}
	return out
}

func ref(t *testing.T, s string) name.Reference {
	t.Helper()
	r, err := name.ParseReference(s, name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// artifact is a Zarf-style OCI artifact: an OCI manifest whose config isn't
// an image config.
func artifact(t *testing.T) v1.Image {
	t.Helper()
	a := mutate.MediaType(bundletest.RandomImage(t), types.OCIManifestSchema1)
	return mutate.ConfigMediaType(a, zarfConfig)
}

func TestToRegistryFullIndexKeepsItsDigest(t *testing.T) {
	host, _ := testRegistry(t)
	index := bundletest.PlatformIndex(t, "linux/amd64", "linux/arm64")
	redis := bundletest.RandomImage(t)
	b, _ := openBundle(t, bundletest.Options{Images: []bundletest.Image{
		{Index: index},
		{Kind: "external", Reference: "redis:7", Image: redis},
	}})

	var out bytes.Buffer
	ms, err := ToRegistry(context.Background(), b, host, nil, true, &out)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := remote.Head(ref(t, host+"/acme/api:2.4.1"))
	if err != nil {
		t.Fatal(err)
	}
	if desc.Digest != digestOf(t, index) {
		t.Fatalf("pushed %s, want the original %s", desc.Digest, digestOf(t, index))
	}
	got, err := remote.Image(ref(t, host+"/docker.io/library/redis:7"))
	if err != nil {
		t.Fatal(err)
	}
	if digestOf(t, got) != digestOf(t, redis) {
		t.Fatal("external image digest changed")
	}
	// Every platform's image is complete.
	pushed, err := remote.Index(ref(t, host+"/acme/api:2.4.1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateIndex(pushed); err != nil {
		t.Fatal(err)
	}

	if len(ms) != 2 || ms[0].ToDigest != ms[0].FromDigest || ms[1].To != host+"/docker.io/library/redis:7" {
		t.Fatalf("mappings %+v", ms)
	}
	want := "registry.breakwaterapp.com/acme/api:2.4.1 -> " + host + "/acme/api:2.4.1@" + digestOf(t, index).String() + "\n"
	if !strings.Contains(out.String(), want) {
		t.Fatalf("output %q lacks %q", out.String(), want)
	}
	if strings.Contains(out.String(), "note:") {
		t.Fatalf("unexpected note: %q", out.String())
	}
}

func validateIndex(idx v1.ImageIndex) error {
	im, err := idx.IndexManifest()
	if err != nil {
		return err
	}
	for _, d := range im.Manifests {
		img, err := idx.Image(d.Digest)
		if err != nil {
			return err
		}
		layers, err := img.Layers()
		if err != nil {
			return err
		}
		for _, l := range layers {
			rc, err := l.Compressed()
			if err != nil {
				return err
			}
			_, err = io.Copy(io.Discard, rc)
			rc.Close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func TestToRegistryOneFilteredChildGoesUnderTheTag(t *testing.T) {
	host, _ := testRegistry(t)
	index := bundletest.PlatformIndex(t, "linux/amd64", "linux/arm64")
	children := childDigests(t, index)
	b, _ := openBundle(t, bundletest.Options{
		Platforms: []string{"linux/amd64"},
		Images:    []bundletest.Image{{Index: index, Children: children[:1]}},
	})
	var out bytes.Buffer
	ms, err := ToRegistry(context.Background(), b, host, nil, true, &out)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := remote.Head(ref(t, host+"/acme/api:2.4.1"))
	if err != nil {
		t.Fatal(err)
	}
	if desc.Digest != children[0] || !desc.MediaType.IsImage() {
		t.Fatalf("got %s %s, want the amd64 child %s", desc.Digest, desc.MediaType, children[0])
	}
	if ms[0].ToDigest != children[0].String() {
		t.Fatalf("mapping %+v", ms[0])
	}
	if !strings.Contains(out.String(), "note: 1 image(s) got a new digest because the bundle keeps only some platforms; use --rewrite-files for files that pin digests.\n") {
		t.Fatalf("output %q", out.String())
	}
}

func TestToRegistryTwoFilteredChildrenGetANewIndex(t *testing.T) {
	host, _ := testRegistry(t)
	base := bundletest.PlatformIndex(t, "linux/amd64", "linux/arm64", "linux/arm/v7")
	index := mutate.Annotations(base, map[string]string{"org.opencontainers.image.source": "https://example.com/acme"}).(v1.ImageIndex)
	children := childDigests(t, index)
	b, _ := openBundle(t, bundletest.Options{
		Platforms: []string{"linux/amd64", "linux/arm64"},
		Images:    []bundletest.Image{{Index: index, Children: children[:2]}},
	})
	ms, err := ToRegistry(context.Background(), b, host, nil, true, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	pushed, err := remote.Index(ref(t, host+"/acme/api:2.4.1"))
	if err != nil {
		t.Fatal(err)
	}
	got := childDigests(t, pushed)
	if len(got) != 2 || got[0] != children[0] || got[1] != children[1] {
		t.Fatalf("pushed children %v, want %v", got, children[:2])
	}
	d := digestOf(t, pushed)
	if d == digestOf(t, index) || ms[0].ToDigest != d.String() || ms[0].FromDigest != digestOf(t, index).String() {
		t.Fatalf("digest %s, mapping %+v", d, ms[0])
	}
	im, _ := pushed.IndexManifest()
	if im.Annotations["org.opencontainers.image.source"] != "https://example.com/acme" || im.MediaType != types.OCIImageIndex {
		t.Fatalf("index fields lost: %+v", im)
	}
	if err := validateIndex(pushed); err != nil {
		t.Fatal(err)
	}
}

func TestToRegistryPushesAnArtifactIntact(t *testing.T) {
	host, _ := testRegistry(t)
	a := artifact(t)
	b, _ := openBundle(t, bundletest.Options{Images: []bundletest.Image{
		{Reference: "registry.breakwaterapp.com/acme/zarf-package:2.4.1", Image: a},
	}})
	if _, err := ToRegistry(context.Background(), b, host+"/mirror", nil, true, io.Discard); err != nil {
		t.Fatal(err)
	}
	desc, err := remote.Get(ref(t, host+"/mirror/acme/zarf-package:2.4.1"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := a.RawManifest()
	if !bytes.Equal(desc.Manifest, raw) {
		t.Fatal("artifact manifest changed")
	}
	img, err := desc.Image()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := img.RawConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := a.RawConfigFile()
	if !bytes.Equal(cfg, want) {
		t.Fatal("artifact config changed")
	}
}

func TestToRegistryKeepsAttestationsOfAFullIndex(t *testing.T) {
	host, _ := testRegistry(t)
	index := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: bundletest.RandomImage(t), Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}},
		mutate.IndexAddendum{Add: bundletest.RandomImage(t), Descriptor: v1.Descriptor{
			Platform:    &v1.Platform{OS: "unknown", Architecture: "unknown"},
			Annotations: map[string]string{"vnd.docker.reference.type": "attestation-manifest"},
		}},
	)
	b, _ := openBundle(t, bundletest.Options{Images: []bundletest.Image{{Index: index}}})
	if _, err := ToRegistry(context.Background(), b, host, nil, true, io.Discard); err != nil {
		t.Fatal(err)
	}
	pushed, err := remote.Index(ref(t, host+"/acme/api:2.4.1"))
	if err != nil {
		t.Fatal(err)
	}
	if digestOf(t, pushed) != digestOf(t, index) {
		t.Fatal("digest changed")
	}
	if err := validateIndex(pushed); err != nil {
		t.Fatal(err)
	}
}

func TestToRegistryFailsWhenABlobChangesAfterOpen(t *testing.T) {
	host, _ := testRegistry(t)
	img := bundletest.RandomImage(t)
	b, path := openBundle(t, bundletest.Options{Images: []bundletest.Image{{Image: img}}})
	layers, _ := img.Layers()
	ld := digestOf(t, layers[1])
	p, _ := bundle.BlobPath(ld.String())
	bundletest.FlipByte(t, path, p)

	_, err := ToRegistry(context.Background(), b, host, nil, true, io.Discard)
	if err == nil {
		t.Fatal("pushed a changed blob")
	}
	if !strings.Contains(err.Error(), "changed after it was verified") {
		t.Fatalf("err = %v", err)
	}
	if _, herr := remote.Head(ref(t, host+"/acme/api:2.4.1")); herr == nil {
		t.Fatal("the tag was pushed")
	}
}

func TestToRegistryRefusesPlainHTTPWithoutInsecure(t *testing.T) {
	host, n := testRegistry(t)
	b, _ := openBundle(t, bundletest.Options{Images: []bundletest.Image{{Image: bundletest.RandomImage(t)}}})
	_, err := ToRegistry(context.Background(), b, host, nil, false, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "refusing plain HTTP to registry "+host) || !strings.Contains(err.Error(), "--insecure") {
		t.Fatalf("err = %v", err)
	}
	if n.Load() != 0 {
		t.Fatalf("%d requests reached the registry", n.Load())
	}
}

func TestToRegistryRefusesBadTargets(t *testing.T) {
	host, n := testRegistry(t)
	// (An unparseable reference like "UPPER/x:1" can't get this far:
	// bundle.Open refuses it.)
	b, _ := openBundle(t, bundletest.Options{Images: []bundletest.Image{{Image: bundletest.RandomImage(t)}}})
	for _, bad := range []string{"", "https://" + host, host + "/", host + "/UPPER", host + ":tag"} {
		if _, err := ToRegistry(context.Background(), b, bad, nil, true, io.Discard); err == nil {
			t.Fatalf("registry %q accepted", bad)
		}
	}
	if n.Load() != 0 {
		t.Fatalf("%d requests reached the registry", n.Load())
	}
}

func TestToRegistryRefusesTwoImagesUnderOneName(t *testing.T) {
	host, n := testRegistry(t)
	b, _ := openBundle(t, bundletest.Options{Images: []bundletest.Image{
		{Kind: "external", Reference: "redis:7", Image: bundletest.RandomImage(t)},
		{Kind: "external", Reference: "docker.io/library/redis:7", Image: bundletest.RandomImage(t)},
	}})
	_, err := ToRegistry(context.Background(), b, host, nil, true, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "both") {
		t.Fatalf("err = %v", err)
	}
	if n.Load() != 0 {
		t.Fatalf("%d requests reached the registry", n.Load())
	}
}

func TestToRegistryExternalImageOnAPort(t *testing.T) {
	host, _ := testRegistry(t)
	img := bundletest.RandomImage(t)
	b, _ := openBundle(t, bundletest.Options{Images: []bundletest.Image{
		{Kind: "external", Reference: "localhost:6000/x:1", Image: img},
	}})
	ms, err := ToRegistry(context.Background(), b, host, nil, true, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if ms[0].To != host+"/localhost_6000/x:1" {
		t.Fatalf("mapping %+v", ms[0])
	}
	desc, err := remote.Head(ref(t, host+"/localhost_6000/x:1"))
	if err != nil || desc.Digest != digestOf(t, img) {
		t.Fatalf("%v %v", desc, err)
	}
}
