package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stympy/breakwater-cli/internal/api"
	"github.com/stympy/breakwater-cli/internal/bundle"
)

// fakeAPI is the customer API for bundle create: the manifest, one file and
// the bundle events.
type fakeAPI struct {
	srv          *httptest.Server
	manifest     api.Manifest
	file         []byte
	startStatus  int
	mu           sync.Mutex
	started      [][]string // platforms of each StartBundle
	completed    []int64    // total_bytes of each CompleteBundle
	authFailures int
}

func (a *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if u, p, _ := r.BasicAuth(); u != "ctok_x" || p != "secret" {
		a.authFailures++
		w.WriteHeader(401)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/v1/customer/products/api/releases/2.4.1":
		json.NewEncoder(w).Encode(a.manifest)
	case r.Method == "GET" && r.URL.Path == "/api/v1/customer/products/api/releases/2.4.1/files/install.sh":
		w.Write(a.file)
	case r.Method == "POST" && r.URL.Path == "/api/v1/customer/products/api/releases/2.4.1/bundles":
		var body struct {
			Platforms []string `json:"platforms"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		a.started = append(a.started, body.Platforms)
		if a.startStatus != 0 {
			w.WriteHeader(a.startStatus)
			w.Write([]byte(`{"error":"boom"}`))
			return
		}
		w.WriteHeader(201)
		w.Write([]byte(`{"data":{"id":"bnd_1"}}`))
	case r.Method == "PATCH" && r.URL.Path == "/api/v1/customer/bundles/bnd_1":
		var body struct {
			Status     string `json:"status"`
			TotalBytes int64  `json:"total_bytes"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.Status != "completed" {
			w.WriteHeader(422)
			return
		}
		a.completed = append(a.completed, body.TotalBytes)
		w.Write([]byte(`{"data":{"id":"bnd_1","status":"completed"}}`))
	default:
		w.WriteHeader(404)
	}
}

// createFixture is an internal multi-platform image (with an attestation)
// on a registry that wants the customer's credentials, an external image on
// another registry that's pulled anonymously, and one file.
type createFixture struct {
	api              *fakeAPI
	internal         string // registry host
	external         string
	externalAuth     *[]string
	corruptBlob      *string // a blob path the internal registry serves flipped
	index            v1.ImageIndex
	out              string
	internalImageRef string
}

func quietRegistry() http.Handler {
	return registry.New(registry.Logger(log.New(io.Discard, "", 0)))
}

func newCreateFixture(t *testing.T) *createFixture {
	t.Helper()
	f := &createFixture{externalAuth: &[]string{}, corruptBlob: new(string)}

	// internal registry
	reg := quietRegistry()
	pushInternal := httptest.NewServer(reg)
	t.Cleanup(pushInternal.Close)
	var corruptMu sync.Mutex
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "ctok_x" || p != "secret" {
			w.Header().Set("WWW-Authenticate", `Basic realm="breakwater"`)
			w.WriteHeader(401)
			return
		}
		corruptMu.Lock()
		bad := *f.corruptBlob
		corruptMu.Unlock()
		if bad != "" && r.Method == "GET" && r.URL.Path == bad {
			rec := httptest.NewRecorder()
			reg.ServeHTTP(rec, r)
			body := rec.Body.Bytes()
			body[len(body)/2] ^= 0xff
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			w.WriteHeader(rec.Code)
			w.Write(body)
			return
		}
		reg.ServeHTTP(w, r)
	}))
	t.Cleanup(internal.Close)
	f.internal = strings.TrimPrefix(internal.URL, "http://")

	// external registry
	ereg := quietRegistry()
	var extMu sync.Mutex
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extMu.Lock()
		*f.externalAuth = append(*f.externalAuth, r.Header.Get("Authorization"))
		extMu.Unlock()
		ereg.ServeHTTP(w, r)
	}))
	t.Cleanup(external.Close)
	f.external = strings.TrimPrefix(external.URL, "http://")

	img := func() v1.Image {
		i, err := random.Image(700, 2)
		if err != nil {
			t.Fatal(err)
		}
		return i
	}
	f.index = mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: img(), Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}},
		mutate.IndexAddendum{Add: img(), Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}}},
		mutate.IndexAddendum{Add: img(), Descriptor: v1.Descriptor{
			Platform:    &v1.Platform{OS: "unknown", Architecture: "unknown"},
			Annotations: map[string]string{"vnd.docker.reference.type": "attestation-manifest"},
		}},
	)
	ref, _ := name.ParseReference(strings.TrimPrefix(pushInternal.URL, "http://") + "/acme/api:2.4.1")
	if err := remote.WriteIndex(ref, f.index); err != nil {
		t.Fatal(err)
	}
	redis, err := mutate.ConfigFile(img(), &v1.ConfigFile{OS: "linux", Architecture: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	eref, _ := name.ParseReference(strings.TrimPrefix(external.URL, "http://") + "/library/redis:7")
	if err := remote.Write(eref, redis); err != nil {
		t.Fatal(err)
	}

	describe := func(x interface {
		Digest() (v1.Hash, error)
		RawManifest() ([]byte, error)
	}) (string, int64) {
		d, _ := x.Digest()
		raw, _ := x.RawManifest()
		return d.String(), int64(len(raw))
	}
	idxDigest, idxSize := describe(f.index)
	idxMT, _ := f.index.MediaType()
	redisDigest, redisSize := describe(redis)
	redisMT, _ := redis.MediaType()

	f.api = &fakeAPI{file: []byte("#!/bin/sh\necho install\n")}
	f.api.srv = httptest.NewServer(f.api)
	t.Cleanup(f.api.srv.Close)
	f.internalImageRef = f.internal + "/acme/api:2.4.1"
	f.api.manifest = api.Manifest{
		Format:      1,
		Vendor:      api.ProductRef{Name: "Acme", Slug: "acme"},
		Product:     api.ProductRef{Name: "API Server", Slug: "api"},
		Version:     "2.4.1",
		PublishedAt: "2026-10-30T12:00:00Z",
		Registry:    f.internal,
		Images: []api.ManifestImage{
			{Kind: "internal", Reference: f.internalImageRef, Digest: idxDigest, MediaType: string(idxMT), Size: idxSize, RepositoryPath: "acme/api", Tag: "2.4.1"},
			{Kind: "external", Reference: f.external + "/library/redis:7", Digest: redisDigest, MediaType: string(redisMT), Size: redisSize},
		},
		Files: []api.ManifestFile{{
			Name: "install.sh", Size: int64(len(f.api.file)), SHA256: sha256Hex(f.api.file),
			URL: f.api.srv.URL + "/api/v1/customer/products/api/releases/2.4.1/files/install.sh",
		}},
	}
	f.out = filepath.Join(t.TempDir(), "api-2.4.1.bwbundle.tar")
	return f
}

func (f *createFixture) args(extra ...string) []string {
	return append([]string{"bundle", "create", "api", "2.4.1",
		"--host", f.api.srv.URL, "--registry-host", f.internal,
		"--insecure-registries", f.internal + "," + f.external,
		"-o", f.out}, extra...)
}

func noPartial(t *testing.T, out string) {
	t.Helper()
	if _, err := os.Stat(out + ".partial"); !os.IsNotExist(err) {
		t.Fatalf("%s.partial exists (%v)", out, err)
	}
}

func TestBundleCreate(t *testing.T) {
	f := newCreateFixture(t)
	ios, out, errb := testIO("", testEnv)
	if code := execute(ios, f.args()); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	noPartial(t, f.out)
	b, err := bundle.Open(f.out)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	h := b.Header()
	if h.Platforms != nil || len(h.Images) != 2 || len(h.Files) != 1 || len(h.Bin) != 1 {
		t.Fatalf("header: platforms %v, %d images, %d files, %d bins", h.Platforms, len(h.Images), len(h.Files), len(h.Bin))
	}
	if len(h.Images[0].Children) != 3 {
		t.Fatalf("children %v", h.Images[0].Children)
	}
	st, _ := os.Stat(f.out)
	if !slices.Equal(f.api.completed, []int64{st.Size()}) {
		t.Fatalf("completed %v, size %d", f.api.completed, st.Size())
	}
	if len(f.api.started) != 1 || !slices.Equal(f.api.started[0], []string{"linux/amd64", "linux/arm64/v8"}) {
		t.Fatalf("started %v", f.api.started)
	}
	for _, a := range *f.externalAuth {
		if a != "" {
			t.Fatalf("the external registry got credentials %q", a)
		}
	}
	for _, want := range []string{"Resolving " + f.internalImageRef + "\n", "Pulling " + f.internalImageRef + " ("} {
		if !strings.Contains(errb.String(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, errb)
		}
	}
	wantOut := fmt.Sprintf("Wrote %s (%s): 2 images, 1 file\n", f.out, humanSize(st.Size()))
	if !strings.HasPrefix(out.String(), wantOut) || !strings.Contains(out.String(), "breakwater bundle load "+f.out+" --docker") {
		t.Fatalf("stdout %q", out)
	}
}

func TestBundleCreateWithPlatform(t *testing.T) {
	f := newCreateFixture(t)
	ios, _, errb := testIO("", testEnv)
	if code := execute(ios, f.args("--platform", "linux/arm64")); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	b, err := bundle.Open(f.out)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	h := b.Header()
	im, _ := f.index.IndexManifest()
	if !slices.Equal(h.Platforms, []string{"linux/arm64"}) || !slices.Equal(h.Images[0].Children, []string{im.Manifests[1].Digest.String()}) {
		t.Fatalf("platforms %v, children %v", h.Platforms, h.Images[0].Children)
	}
	// The amd64 image's layers aren't in the bundle.
	amd, _ := f.index.Image(im.Manifests[0].Digest)
	layers, _ := amd.Layers()
	d, _ := layers[0].Digest()
	if p, _ := bundle.BlobPath(d.String()); func() bool { _, ok := b.Index().Lookup(p); return ok }() {
		t.Fatal("a filtered-out layer is in the bundle")
	}
	if len(f.api.started) != 1 || !slices.Equal(f.api.started[0], []string{"linux/arm64"}) {
		t.Fatalf("started %v", f.api.started)
	}
}

func TestBundleCreateUnknownPlatform(t *testing.T) {
	f := newCreateFixture(t)
	ios, _, errb := testIO("", testEnv)
	if code := execute(ios, f.args("--platform", "linux/s390x")); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "has no manifest for linux/s390x; it has linux/amd64, linux/arm64/v8") {
		t.Fatalf("stderr %q", errb)
	}
	if _, err := os.Stat(f.out); !os.IsNotExist(err) {
		t.Fatal("output written")
	}
	if len(f.api.started) != 0 {
		t.Fatal("bundle event started")
	}
}

func TestBundleCreateInvalidPlatform(t *testing.T) {
	f := newCreateFixture(t)
	ios, _, errb := testIO("", testEnv)
	if code := execute(ios, f.args("--platform", "Linux/AMD64")); code != 1 || !strings.Contains(errb.String(), `invalid platform "Linux/AMD64"`) {
		t.Fatalf("exit %d: %s", code, errb)
	}
}

func TestBundleCreateStartFailureStillWrites(t *testing.T) {
	f := newCreateFixture(t)
	f.api.startStatus = 500
	ios, _, errb := testIO("", testEnv)
	if code := execute(ios, f.args()); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if !strings.Contains(errb.String(), "warning: couldn't record the bundle with Breakwater: Breakwater API returned 500") {
		t.Fatalf("stderr %q", errb)
	}
	b, err := bundle.Open(f.out)
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
	if len(f.api.completed) != 0 {
		t.Fatal("completed a bundle that never started")
	}
}

func TestBundleCreateCorruptBlobLeavesNothing(t *testing.T) {
	f := newCreateFixture(t)
	im, _ := f.index.IndexManifest()
	child, _ := f.index.Image(im.Manifests[1].Digest)
	layers, _ := child.Layers()
	d, _ := layers[1].Digest()
	*f.corruptBlob = "/v2/acme/api/blobs/" + d.String()

	ios, _, errb := testIO("", testEnv)
	if code := execute(ios, f.args()); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), d.String()) {
		t.Fatalf("the error doesn't name the blob: %s", errb)
	}
	if _, err := os.Stat(f.out); !os.IsNotExist(err) {
		t.Fatal("output written")
	}
	noPartial(t, f.out)
	if len(f.api.started) != 1 || len(f.api.completed) != 0 {
		t.Fatalf("started %v, completed %v", f.api.started, f.api.completed)
	}
}

func TestBundleCreateRefusesExistingOutput(t *testing.T) {
	f := newCreateFixture(t)
	if err := os.WriteFile(f.out, []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}
	ios, _, errb := testIO("", testEnv)
	if code := execute(ios, f.args()); code != 1 || !strings.Contains(errb.String(), "already exists") {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if data, _ := os.ReadFile(f.out); string(data) != "keep me" {
		t.Fatal("output overwritten")
	}
	if len(f.api.started) != 0 {
		t.Fatal("bundle event started")
	}

	ios, _, errb = testIO("", testEnv)
	if code := execute(ios, f.args("--force")); code != 0 {
		t.Fatalf("--force: exit %d: %s", code, errb)
	}
	b, err := bundle.Open(f.out)
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
}

func TestBundleCreateInternalImageOffHost(t *testing.T) {
	f := newCreateFixture(t)
	ios, _, errb := testIO("", testEnv)
	args := f.args()
	for i, a := range args {
		if a == "--registry-host" {
			args[i+1] = "registry.breakwaterapp.com"
		}
	}
	if code := execute(ios, args); code != 1 || !strings.Contains(errb.String(), "is marked internal but isn't on registry.breakwaterapp.com") {
		t.Fatalf("exit %d: %s", code, errb)
	}
}

func TestDefaultBundleName(t *testing.T) {
	if got := defaultBundleName("api", "2.4.1+build.5"); got != "api-2.4.1+build.5.bwbundle.tar" {
		t.Fatal(got)
	}
}

func TestEventPlatforms(t *testing.T) {
	if got := eventPlatforms(nil, nil); !slices.Equal(got, []string{"unknown/unknown"}) {
		t.Fatalf("empty: %v", got)
	}
	var many []string
	for i := 0; i < 20; i++ {
		many = append(many, fmt.Sprintf("linux/arch%02d", i))
	}
	if got := eventPlatforms(nil, [][]string{many, {"linux/amd64", "Bad/Platform"}}); len(got) != 16 || got[0] != "linux/amd64" {
		t.Fatalf("union: %v", got)
	}
	if got := eventPlatforms([]string{"linux/arm64", "linux/amd64"}, [][]string{{"windows/amd64"}}); !slices.Equal(got, []string{"linux/arm64", "linux/amd64"}) {
		t.Fatalf("requested: %v", got)
	}
}

func sha256Hex(b []byte) string {
	h, _, _ := v1.SHA256(strings.NewReader(string(b)))
	return h.Hex
}
