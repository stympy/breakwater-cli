package images

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stympy/breakwater-cli/internal/api"
)

// testRegistry is an in-memory registry. Push through PushHost (no auth,
// no wrapping); collect through Host, whose handler is wrap(registry).
type testRegistry struct {
	Host     string
	PushHost string
}

func newTestRegistry(t *testing.T, wrap func(http.Handler) http.Handler) *testRegistry {
	t.Helper()
	reg := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	push := httptest.NewServer(reg)
	t.Cleanup(push.Close)
	h := http.Handler(reg)
	if wrap != nil {
		h = wrap(reg)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &testRegistry{Host: strings.TrimPrefix(srv.URL, "http://"), PushHost: strings.TrimPrefix(push.URL, "http://")}
}

func randomImage(t *testing.T) v1.Image {
	t.Helper()
	img, err := random.Image(512, 2)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

// multiPlatformIndex has linux/amd64 and linux/arm64/v8 images and a buildx
// attestation manifest.
func multiPlatformIndex(t *testing.T) v1.ImageIndex {
	t.Helper()
	att := mutate.IndexAddendum{
		Add: randomImage(t),
		Descriptor: v1.Descriptor{
			Platform:    &v1.Platform{OS: "unknown", Architecture: "unknown"},
			Annotations: map[string]string{"vnd.docker.reference.type": "attestation-manifest"},
		},
	}
	return mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: randomImage(t), Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}},
		mutate.IndexAddendum{Add: randomImage(t), Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}}},
		att,
	)
}

type pushable interface {
	Digest() (v1.Hash, error)
	MediaType() (types.MediaType, error)
	RawManifest() ([]byte, error)
}

// push writes an image or index to the registry and returns its manifest
// entry, on the collecting host.
func (r *testRegistry) push(t *testing.T, repoTag, kind string, x pushable) api.ManifestImage {
	t.Helper()
	ref, err := name.ParseReference(r.PushHost + "/" + repoTag)
	if err != nil {
		t.Fatal(err)
	}
	switch v := x.(type) {
	case v1.ImageIndex:
		err = remote.WriteIndex(ref, v)
	case v1.Image:
		err = remote.Write(ref, v)
	}
	if err != nil {
		t.Fatal(err)
	}
	return manifestImage(t, r.Host, repoTag, kind, x)
}

func manifestImage(t *testing.T, host, repoTag, kind string, x pushable) api.ManifestImage {
	t.Helper()
	d, _ := x.Digest()
	mt, _ := x.MediaType()
	raw, _ := x.RawManifest()
	repo, tag, _ := strings.Cut(repoTag, ":")
	mi := api.ManifestImage{Kind: kind, Reference: host + "/" + repoTag, Digest: d.String(), MediaType: string(mt), Size: int64(len(raw)), Tag: tag}
	if kind == "internal" {
		mi.RepositoryPath = repo
	}
	return mi
}

func collector(r *testRegistry, hosts ...string) *Collector {
	return &Collector{
		RegistryHost:       r.Host,
		Auth:               &authn.Basic{Username: "ctok_x", Password: "secret"},
		UserAgent:          "breakwater-cli/test",
		InsecureRegistries: append([]string{r.Host}, hosts...),
	}
}

func TestResolveIndexAllPlatforms(t *testing.T) {
	r := newTestRegistry(t, nil)
	idx := multiPlatformIndex(t)
	mi := r.push(t, "acme/api:2.4.1", "internal", idx)
	res, err := collector(r).Resolve(context.Background(), mi, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Children) != 3 {
		t.Fatalf("children %v", res.Children)
	}
	// top index + 3 manifests; 3 configs + 6 layers
	if len(res.Manifests) != 4 || len(res.Blobs) != 9 {
		t.Fatalf("manifests %d, blobs %d", len(res.Manifests), len(res.Blobs))
	}
	if res.Manifests[0].Digest.String() != mi.Digest || res.Manifests[0].MediaType != types.OCIImageIndex {
		t.Fatalf("top manifest %v %s", res.Manifests[0].Digest, res.Manifests[0].MediaType)
	}
	if !slices.Equal(res.Platforms, []string{"linux/amd64", "linux/arm64/v8"}) {
		t.Fatalf("platforms %v", res.Platforms)
	}
}

func TestResolveIndexFiltersPlatformsAndAttestations(t *testing.T) {
	r := newTestRegistry(t, nil)
	idx := multiPlatformIndex(t)
	mi := r.push(t, "acme/api:2.4.1", "internal", idx)
	im, _ := idx.IndexManifest()
	for _, tc := range []struct {
		platform string
		child    int
	}{{"linux/amd64", 0}, {"linux/arm64", 1}, {"linux/arm64/v8", 1}} {
		res, err := collector(r).Resolve(context.Background(), mi, []string{tc.platform})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(res.Children, []string{im.Manifests[tc.child].Digest.String()}) {
			t.Fatalf("%s: children %v", tc.platform, res.Children)
		}
		if len(res.Manifests) != 2 || len(res.Blobs) != 3 {
			t.Fatalf("%s: manifests %d, blobs %d", tc.platform, len(res.Manifests), len(res.Blobs))
		}
	}
}

func TestResolveUnknownPlatformListsAvailable(t *testing.T) {
	r := newTestRegistry(t, nil)
	mi := r.push(t, "acme/api:2.4.1", "internal", multiPlatformIndex(t))
	_, err := collector(r).Resolve(context.Background(), mi, []string{"linux/s390x", "linux/arm64/v7"})
	if err == nil {
		t.Fatal("expected an error")
	}
	want := "image " + mi.Reference + " has no manifest for linux/s390x, linux/arm64/v7; it has linux/amd64, linux/arm64/v8"
	if err.Error() != want {
		t.Fatalf("got %q\nwant %q", err, want)
	}
}

func TestResolveInternalOffHost(t *testing.T) {
	r := newTestRegistry(t, nil)
	mi := r.push(t, "acme/api:2.4.1", "internal", randomImage(t))
	c := collector(r)
	c.RegistryHost = "registry.breakwaterapp.com"
	_, err := c.Resolve(context.Background(), mi, nil)
	if err == nil || !strings.Contains(err.Error(), "is marked internal but isn't on registry.breakwaterapp.com") {
		t.Fatalf("got %v", err)
	}
}

func TestResolveChecksDigestAndSize(t *testing.T) {
	r := newTestRegistry(t, nil)
	img := randomImage(t)
	mi := r.push(t, "acme/api:2.4.1", "internal", img)
	wrong := mi
	wrong.Size++
	if _, err := collector(r).Resolve(context.Background(), wrong, nil); err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("size mismatch: %v", err)
	}

	wrong = mi
	wrong.MediaType = string(types.OCIImageIndex)
	if _, err := collector(r).Resolve(context.Background(), wrong, nil); err == nil || !strings.Contains(err.Error(), "media type") {
		t.Fatalf("media type mismatch: %v", err)
	}
}

// A registry that serves other bytes for a manifest digest is refused.
func TestResolveRefusesAManifestNotMatchingItsDigest(t *testing.T) {
	var swap struct {
		sync.Mutex
		path string
		body []byte
	}
	r := newTestRegistry(t, func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			swap.Lock()
			path, body := swap.path, swap.body
			swap.Unlock()
			if path != "" && req.URL.Path == path {
				w.Header().Set("Content-Type", string(types.DockerManifestSchema2))
				w.Header().Set("Content-Length", strconv.Itoa(len(body)))
				if req.Method == http.MethodGet {
					w.Write(body)
				}
				return
			}
			h.ServeHTTP(w, req)
		})
	})
	img := randomImage(t)
	mi := r.push(t, "acme/api:2.4.1", "internal", img)
	raw, _ := img.RawManifest()
	cfg, _ := img.ConfigName()
	// Same length, one hex digit of the config digest changed.
	flipped := cfg.Hex[:63] + map[bool]string{true: "0", false: "1"}[cfg.Hex[63] != '0']
	evil := bytes.Replace(raw, []byte(cfg.Hex), []byte(flipped), 1)
	swap.Lock()
	swap.path, swap.body = "/v2/acme/api/manifests/"+mi.Digest, evil
	swap.Unlock()
	_, err := collector(r).Resolve(context.Background(), mi, nil)
	if err == nil {
		t.Fatal("a manifest not matching its digest passed")
	}
}

func TestResolveArtifactHasNoPlatforms(t *testing.T) {
	r := newTestRegistry(t, nil)
	layer, err := random.Layer(300, types.MediaType("application/vnd.zarf.layer.v1.tar"))
	if err != nil {
		t.Fatal(err)
	}
	art, err := mutate.AppendLayers(mutate.MediaType(empty.Image, types.OCIManifestSchema1), layer)
	if err != nil {
		t.Fatal(err)
	}
	art = mutate.ConfigMediaType(art, "application/vnd.zarf.config.v1+json")
	mi := r.push(t, "acme/zarf:1.0.0", "internal", art)
	res, err := collector(r).Resolve(context.Background(), mi, []string{"linux/amd64"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Platforms) != 0 || len(res.Children) != 0 || len(res.Blobs) != 2 || len(res.Manifests) != 1 {
		t.Fatalf("platforms %v, children %v, blobs %d, manifests %d", res.Platforms, res.Children, len(res.Blobs), len(res.Manifests))
	}
}

func TestResolveImagePlatformFromConfig(t *testing.T) {
	r := newTestRegistry(t, nil)
	img, err := mutate.ConfigFile(randomImage(t), &v1.ConfigFile{OS: "linux", Architecture: "arm", Variant: "v7"})
	if err != nil {
		t.Fatal(err)
	}
	mi := r.push(t, "acme/api:2.4.1", "internal", img)
	res, err := collector(r).Resolve(context.Background(), mi, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(res.Platforms, []string{"linux/arm/v7"}) {
		t.Fatalf("platforms %v", res.Platforms)
	}
}

func TestFetchBlobStreamsLayers(t *testing.T) {
	r := newTestRegistry(t, nil)
	img := randomImage(t)
	mi := r.push(t, "acme/api:2.4.1", "internal", img)
	c := collector(r)
	res, err := c.Resolve(context.Background(), mi, nil)
	if err != nil {
		t.Fatal(err)
	}
	layers, _ := img.Layers()
	want, _ := layers[1].Digest()
	var d v1.Descriptor
	for _, b := range res.Blobs {
		if b.Digest == want {
			d = b
		}
	}
	rc, err := c.FetchBlob(context.Background(), res, d)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	h, _, _ := v1.SHA256(bytes.NewReader(got))
	if h != want {
		t.Fatalf("got %s, want %s", h, want)
	}
}

// --- Credential leaks ---

type authLog struct {
	sync.Mutex
	seen []string // "METHOD path auth"
}

func (l *authLog) record(r *http.Request) {
	l.Lock()
	defer l.Unlock()
	l.seen = append(l.seen, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
}

func (l *authLog) all() []string {
	l.Lock()
	defer l.Unlock()
	return slices.Clone(l.seen)
}

// requireBasic answers 401 with a Basic challenge unless the request has
// the test credentials.
func requireBasic(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "ctok_x" || p != "secret" {
			w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// A blob GET redirected to storage on another host goes there without
// Authorization, and the blob still arrives.
func TestBlobRedirectCarriesNoCredentials(t *testing.T) {
	var storageLog authLog
	var storageURL string
	r := newTestRegistry(t, func(reg http.Handler) http.Handler {
		storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			storageLog.record(req)
			req.Header.Del("Authorization")
			reg.ServeHTTP(w, req)
		}))
		t.Cleanup(storage.Close)
		storageURL = storage.URL
		return requireBasic(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/blobs/") {
				http.Redirect(w, req, storageURL+req.URL.Path, http.StatusTemporaryRedirect)
				return
			}
			reg.ServeHTTP(w, req)
		}))
	})
	img := randomImage(t)
	mi := r.push(t, "acme/api:2.4.1", "internal", img)
	c := collector(r)
	res, err := c.Resolve(context.Background(), mi, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Blobs {
		rc, err := c.FetchBlob(context.Background(), res, d)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		if h, _, _ := v1.SHA256(bytes.NewReader(got)); h != d.Digest {
			t.Fatalf("blob %s arrived as %s", d.Digest, h)
		}
	}
	seen := storageLog.all()
	if len(seen) < len(res.Blobs) {
		t.Fatalf("storage saw %v", seen)
	}
	for _, s := range seen {
		if !strings.HasSuffix(s, " ") {
			t.Fatalf("storage got credentials: %q", s)
		}
	}
}

func TestExternalImagesArePulledAnonymously(t *testing.T) {
	var reqs authLog
	r := newTestRegistry(t, func(reg http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			reqs.record(req)
			reg.ServeHTTP(w, req)
		})
	})
	idx := multiPlatformIndex(t)
	external := r.push(t, "library/redis:7", "external", idx)
	c := collector(r)
	c.RegistryHost = "registry.breakwaterapp.com" // the external registry isn't it
	res, err := c.Resolve(context.Background(), external, nil)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := c.FetchBlob(context.Background(), res, res.Blobs[0])
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, rc)
	rc.Close()
	externalSeen := reqs.all()
	if len(externalSeen) == 0 {
		t.Fatal("no requests recorded")
	}
	for _, s := range externalSeen {
		if !strings.HasSuffix(s, " ") {
			t.Fatalf("external request carried credentials: %q", s)
		}
	}

	// The same registry as the internal one: credentials go.
	internal := manifestImage(t, r.Host, "acme/api:2.4.1", "internal", idx)
	r.push(t, "acme/api:2.4.1", "internal", idx)
	c = collector(r)
	n := len(reqs.all())
	if _, err := c.Resolve(context.Background(), internal, nil); err != nil {
		t.Fatal(err)
	}
	basic := 0
	for _, s := range reqs.all()[n:] {
		if strings.Contains(s, " Basic ") {
			basic++
		}
	}
	if basic == 0 {
		t.Fatalf("internal requests carried no Basic auth: %v", reqs.all()[n:])
	}
}

func TestResolveRefusesSchema1(t *testing.T) {
	body := []byte(`{"schemaVersion":1,"name":"acme/old","tag":"1","architecture":"amd64","fsLayers":[],"history":[]}`)
	h, _, _ := v1.SHA256(bytes.NewReader(body))
	r := newTestRegistry(t, func(reg http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.URL.Path == "/v2/acme/old/manifests/"+h.String() {
				w.Header().Set("Content-Type", string(types.DockerManifestSchema1))
				w.Header().Set("Docker-Content-Digest", h.String())
				w.Header().Set("Content-Length", strconv.Itoa(len(body)))
				w.Write(body)
				return
			}
			reg.ServeHTTP(w, req)
		})
	})
	mi := api.ManifestImage{Kind: "internal", Reference: r.Host + "/acme/old:1", Digest: h.String(), MediaType: string(types.DockerManifestSchema1), Size: int64(len(body)), RepositoryPath: "acme/old", Tag: "1"}
	_, err := collector(r).Resolve(context.Background(), mi, nil)
	if err == nil || !strings.Contains(err.Error(), "uses Docker schema 1, which isn't supported") {
		t.Fatalf("got %v", err)
	}
}

// A foreign (non-distributable) layer, one with urls, is fetched from the
// registry like any other layer; when the registry doesn't have it, the
// error names it.
func TestForeignLayersComeFromTheRegistry(t *testing.T) {
	foreign, err := random.Layer(400, types.DockerForeignLayer)
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.Append(randomImage(t), mutate.Addendum{
		Layer: foreign, MediaType: types.DockerForeignLayer, URLs: []string{"https://example.com/layer"},
	})
	if err != nil {
		t.Fatal(err)
	}
	fd, _ := foreign.Digest()
	for _, uploaded := range []bool{true, false} {
		r := newTestRegistry(t, nil) // its blob store is shared by repositories
		repoTag := "acme/win:1"
		ref, _ := name.ParseReference(r.PushHost + "/" + repoTag)
		opts := []remote.Option{}
		if uploaded {
			opts = append(opts, remote.WithNondistributable)
		}
		if err := remote.Write(ref, img, opts...); err != nil {
			t.Fatal(err)
		}
		mi := manifestImage(t, r.Host, repoTag, "internal", img)
		c := collector(r)
		res, err := c.Resolve(context.Background(), mi, nil)
		if err != nil {
			t.Fatal(err)
		}
		var d v1.Descriptor
		for _, b := range res.Blobs {
			if b.Digest == fd {
				d = b
			}
		}
		if len(d.URLs) == 0 {
			t.Fatalf("the foreign layer isn't among the blobs: %v", res.Blobs)
		}
		rc, err := c.FetchBlob(context.Background(), res, d)
		if err == nil {
			_, err = io.Copy(io.Discard, rc)
			rc.Close()
		}
		if uploaded && err != nil {
			t.Fatalf("uploaded: %v", err)
		}
		if !uploaded && err == nil {
			t.Fatal("a missing foreign layer was fetched")
		}
		if !uploaded {
			t.Logf("missing foreign layer: %v", err)
		}
	}
}

// A registry on a loopback host not listed as insecure is reached only over
// HTTPS: ggcr's localhost fallback to plain HTTP is refused.
func TestUnlistedLocalRegistryIsNotReachedOverHTTP(t *testing.T) {
	var plain authLog
	r := newTestRegistry(t, func(reg http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			plain.record(req)
			reg.ServeHTTP(w, req)
		})
	})
	img := randomImage(t)
	for _, kind := range []string{"internal", "external"} {
		mi := r.push(t, "acme/api:2.4.1", kind, img)
		c := collector(r)
		c.InsecureRegistries = nil
		if _, err := c.Resolve(context.Background(), mi, nil); err == nil {
			t.Fatalf("%s: resolved over plain HTTP", kind)
		}
	}
	if seen := plain.all(); len(seen) != 0 {
		t.Fatalf("the plain-HTTP registry was contacted: %v", seen)
	}
}

// The bearer flow: the token endpoint gets Basic credentials, the registry
// gets the bearer token, and a blob redirect to storage carries neither.
func TestBearerFlowBlobRedirectCarriesNoCredentials(t *testing.T) {
	var storageLog, tokenLog authLog
	var registryURL string
	r := newTestRegistry(t, func(reg http.Handler) http.Handler {
		storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			storageLog.record(req)
			req.Header.Del("Authorization")
			reg.ServeHTTP(w, req)
		}))
		t.Cleanup(storage.Close)
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.URL.Path == "/token" {
				tokenLog.record(req)
				if u, p, ok := req.BasicAuth(); !ok || u != "ctok_x" || p != "secret" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"token":"tok123","access_token":"tok123"}`))
				return
			}
			if req.Header.Get("Authorization") != "Bearer tok123" {
				w.Header().Set("WWW-Authenticate", `Bearer realm="`+registryURL+`/token",service="test"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/blobs/") {
				http.Redirect(w, req, storage.URL+req.URL.Path, http.StatusTemporaryRedirect)
				return
			}
			reg.ServeHTTP(w, req)
		})
	})
	registryURL = "http://" + r.Host
	img := randomImage(t)
	mi := r.push(t, "acme/api:2.4.1", "internal", img)
	c := collector(r)
	res, err := c.Resolve(context.Background(), mi, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range res.Blobs {
		rc, err := c.FetchBlob(context.Background(), res, d)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		if h, _, _ := v1.SHA256(bytes.NewReader(got)); h != d.Digest {
			t.Fatalf("blob %s arrived as %s", d.Digest, h)
		}
	}
	tokens := tokenLog.all()
	if len(tokens) == 0 {
		t.Fatal("the token endpoint was never called")
	}
	for _, s := range tokens {
		if !strings.Contains(s, " Basic ") {
			t.Fatalf("token request without Basic: %q", s)
		}
	}
	seen := storageLog.all()
	if len(seen) < len(res.Blobs) {
		t.Fatalf("storage saw %v", seen)
	}
	for _, s := range seen {
		if !strings.HasSuffix(s, " ") {
			t.Fatalf("storage got credentials: %q", s)
		}
	}
}
