//go:build integration

// Package integration runs the real binary against a real registry:2. Start
// one with script/integration, which sets BW_TEST_REGISTRY.
package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stympy/breakwater-cli/internal/api"
)

func run(t *testing.T, bin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "BREAKWATER_USERNAME=ctok_test", "BREAKWATER_TOKEN=secret")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("breakwater %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func hash(t *testing.T, i api.ManifestImage) v1.Hash {
	h, err := v1.NewHash(i.Digest)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestCreateVerifyLoadAgainstRegistry(t *testing.T) {
	host := os.Getenv("BW_TEST_REGISTRY")
	if host == "" {
		t.Skip("BW_TEST_REGISTRY not set; run script/integration")
	}

	bin := filepath.Join(t.TempDir(), "breakwater")
	if out, err := exec.Command("go", "build", "-o", bin, "../cmd/breakwater").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	img := func() v1.Image {
		i, err := random.Image(2048, 2)
		if err != nil {
			t.Fatal(err)
		}
		i, err = mutate.ConfigFile(i, &v1.ConfigFile{OS: "linux", Architecture: "amd64"})
		if err != nil {
			t.Fatal(err)
		}
		return i
	}
	index := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: img(), Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}},
		mutate.IndexAddendum{Add: img(), Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64"}}},
	)
	single := img()

	describe := func(path string, obj interface {
		Digest() (v1.Hash, error)
		RawManifest() ([]byte, error)
	}, mt string) api.ManifestImage {
		d, _ := obj.Digest()
		raw, _ := obj.RawManifest()
		repo, tag, _ := strings.Cut(path, ":")
		return api.ManifestImage{Kind: "internal", Reference: host + "/" + path, Digest: d.String(),
			MediaType: mt, Size: int64(len(raw)), RepositoryPath: repo, Tag: tag}
	}

	indexRef, _ := name.ParseReference(host+"/acme/api:1.0.0", name.Insecure)
	if err := remote.WriteIndex(indexRef, index); err != nil {
		t.Fatal(err)
	}
	singleRef, _ := name.ParseReference(host+"/acme/worker:1.0.0", name.Insecure)
	if err := remote.Write(singleRef, single); err != nil {
		t.Fatal(err)
	}
	indexMT, _ := index.MediaType()
	singleMT, _ := single.MediaType()
	images := []api.ManifestImage{
		describe("acme/api:1.0.0", index, string(indexMT)),
		describe("acme/worker:1.0.0", single, string(singleMT)),
	}

	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/v1/customer/products/api/releases/1.0.0":
			json.NewEncoder(w).Encode(api.Manifest{
				Format: 1, Vendor: api.ProductRef{Name: "Acme", Slug: "acme"},
				Product: api.ProductRef{Name: "API", Slug: "api"}, Version: "1.0.0",
				PublishedAt: "2026-10-30T12:00:00Z", Registry: host, Images: images,
			})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/bundles"):
			w.WriteHeader(201)
			w.Write([]byte(`{"data":{"id":"bnd_1"}}`))
		case r.Method == "PATCH":
			w.Write([]byte(`{"data":{"id":"bnd_1","status":"completed"}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer stub.Close()

	file := filepath.Join(t.TempDir(), "api-1.0.0.bwbundle.tar")
	run(t, bin, "bundle", "create", "api", "1.0.0",
		"--host", stub.URL, "--registry-host", host, "--insecure-registries", host,
		"--platform", "linux/amd64,linux/arm64", "-o", file)
	run(t, bin, "bundle", "verify", file)
	run(t, bin, "bundle", "load", file, "--registry", host+"/mirror", "--insecure")

	for path, want := range map[string]v1.Hash{
		"mirror/acme/api:1.0.0":    hash(t, images[0]),
		"mirror/acme/worker:1.0.0": hash(t, images[1]),
	} {
		ref, _ := name.ParseReference(host+"/"+path, name.Insecure)
		desc, err := remote.Head(ref)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if desc.Digest != want {
			t.Errorf("%s digest = %s, want %s", path, desc.Digest, want)
		}
	}
}
