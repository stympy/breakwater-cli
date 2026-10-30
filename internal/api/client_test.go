package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stympy/breakwater-cli/internal/credentials"
)

var creds = credentials.Credentials{Username: "ctok_abc", Password: "secret"}

func newClient(t *testing.T, h http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return New(u, creds), srv
}

func okManifest() map[string]any {
	return map[string]any{
		"format": 1, "vendor": map[string]any{"name": "V", "slug": "v"}, "product": map[string]any{"name": "P", "slug": "p"},
		"version": "1.0.0", "incomplete": false, "incomplete_reasons": []string{}, "registry": "r.example",
		"images": []any{map[string]any{"kind": "internal", "reference": "r.example/v/app:1", "digest": "sha256:" + strings.Repeat("a", 64),
			"media_type": "m", "size": 5, "tag": "1", "repository_path": "v/app"}},
		"files": []any{},
	}
}

func serveJSON(v any) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(v)
	})
}

func TestAuthAndUserAgentSent(t *testing.T) {
	var gotUA, gotUser, gotPass, gotPath, gotQuery string
	c, _ := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.UserAgent()
		gotUser, gotPass, _ = r.BasicAuth()
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		w.Write([]byte(`{"data":[{"product":{"name":"P","slug":"p"},"version":"1","published_at":"2026-01-02T03:04:05Z"}]}`))
	}))
	rs, err := c.Releases(context.Background(), "p")
	if err != nil {
		t.Fatal(err)
	}
	if gotUA != "breakwater-cli/dev" || gotUser != "ctok_abc" || gotPass != "secret" {
		t.Fatalf("ua %q user %q pass %q", gotUA, gotUser, gotPass)
	}
	if gotPath != "/api/v1/customer/releases" || gotQuery != "product=p" || len(rs) != 1 || rs[0].Version != "1" {
		t.Fatalf("path %q query %q rs %v", gotPath, gotQuery, rs)
	}
}

func TestErrorStatusMapping(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		header  map[string]string
		want    string
		useMani bool
	}{
		{"401", 401, `{"error":"Unauthorized"}`, nil, `the API refused the credentials (use a customer pull token)`, false},
		{"403 plan", 403, `{"error":"plan_required"}`, nil, `air-gapped bundles aren't included in this vendor's Breakwater plan`, false},
		{"403 other", 403, `{"error":"nope"}`, nil, `Breakwater API returned 403: nope`, false},
		{"404 manifest", 404, `{"error":"Resource not found"}`, nil, `no release 1.0.0 of p that this token can see`, true},
		{"429", 429, `{}`, map[string]string{"Retry-After": "7"}, `rate limited by Breakwater; try again in 7s`, false},
		{"429 none", 429, `{}`, nil, `rate limited by Breakwater; try again later`, false},
		{"429 date", 429, `{}`, map[string]string{"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}, `rate limited by Breakwater; try again later`, false},
		{"500 json", 500, `{"error":"boom"}`, nil, `Breakwater API returned 500: boom`, false},
		{"500 body", 500, `<html>oops</html>`, nil, `Breakwater API returned 500: <html>oops</html>`, false},
		{"422 details", 422, `{"error":"Validation failed","details":["platforms bad","x"]}`, nil, `Breakwater API returned 422: Validation failed: platforms bad; x`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tc.header {
					w.Header().Set(k, v)
				}
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			var err error
			if tc.useMani {
				_, _, err = c.Manifest(context.Background(), "p", "1.0.0")
			} else {
				_, err = c.Releases(context.Background(), "")
			}
			var ae *Error
			if err == nil || !asError(err, &ae) || ae.Status != tc.status || ae.Message != tc.want {
				t.Fatalf("got %#v, want %q", err, tc.want)
			}
		})
	}
}

func asError(err error, target **Error) bool {
	e, ok := err.(*Error)
	if ok {
		*target = e
	}
	return ok
}

func TestRedirectRefusedAndNotFollowed(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer other.Close()
	c, _ := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/x", http.StatusFound)
	}))
	_, err := c.Releases(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "redirected to "+other.URL+"/x; refusing to follow with credentials") {
		t.Fatalf("err %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("redirect target was hit")
	}
}

func TestWithHTTPClientKeepsRedirectsRefused(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	c := New(u, creds, WithHTTPClient(&http.Client{}))
	if _, err := c.Releases(context.Background(), ""); err == nil || hits.Load() != 0 {
		t.Fatalf("err %v hits %d", err, hits.Load())
	}
}

func TestManifestRefusals(t *testing.T) {
	mod := func(f func(m map[string]any)) map[string]any {
		m := okManifest()
		f(m)
		return m
	}
	img := func(m map[string]any) map[string]any { return m["images"].([]any)[0].(map[string]any) }
	sha := strings.Repeat("b", 64)
	file := func(name string, size int, sum string) map[string]any {
		return map[string]any{"name": name, "size": size, "sha256": sum, "url": "http://x/f"}
	}
	cases := []struct {
		name string
		m    map[string]any
		want string
	}{
		{"format 2", mod(func(m map[string]any) { m["format"] = 2 }), "this release uses manifest format 2; upgrade breakwater"},
		{"incomplete", mod(func(m map[string]any) {
			m["incomplete"] = true
			m["incomplete_reasons"] = []string{"image a is missing", "image b is missing"}
		}), "image a is missing; image b is missing"},
		{"at in reference", mod(func(m map[string]any) { img(m)["reference"] = "r.example/v/app@sha256:" + strings.Repeat("a", 64) }), "must not contain a digest"},
		{"bad digest", mod(func(m map[string]any) { img(m)["digest"] = "sha256:ABC" }), "invalid digest"},
		{"bad kind", mod(func(m map[string]any) { img(m)["kind"] = "weird" }), "unknown kind"},
		{"internal no path", mod(func(m map[string]any) { img(m)["repository_path"] = "" }), "no repository_path or tag"},
		{"other product", mod(func(m map[string]any) { m["product"] = map[string]any{"name": "X", "slug": "other"} }), `for product "other", not "p"`},
		{"other version", mod(func(m map[string]any) { m["version"] = "9.9.9" }), `for version "9.9.9", not "1.0.0"`},
		{"file bad name", mod(func(m map[string]any) { m["files"] = []any{file("../x", 1, sha)} }), "isn't allowed"},
		{"file dup", mod(func(m map[string]any) { m["files"] = []any{file("a", 1, sha), file("a", 2, sha)} }), "twice"},
		{"file upper sha", mod(func(m map[string]any) { m["files"] = []any{file("a", 1, strings.ToUpper(sha))} }), "invalid sha256"},
		{"file short sha", mod(func(m map[string]any) { m["files"] = []any{file("a", 1, "abc")} }), "invalid sha256"},
		{"file negative size", mod(func(m map[string]any) { m["files"] = []any{file("a", -1, sha)} }), "invalid size"},
		{"internal no tag", mod(func(m map[string]any) { img(m)["tag"] = "" }), "no repository_path or tag"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newClient(t, serveJSON(tc.m))
			_, _, err := c.Manifest(context.Background(), "p", "1.0.0")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
}

func TestManifestOKAndRawAndPathEscaping(t *testing.T) {
	var rawPath string
	c, _ := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawPath = r.URL.EscapedPath()
		m := okManifest()
		m["product"] = map[string]any{"name": "P", "slug": "my prod"}
		m["version"] = "2.4.1+build.5/x"
		json.NewEncoder(w).Encode(m)
	}))
	m, raw, err := c.Manifest(context.Background(), "my prod", "2.4.1+build.5/x")
	if err != nil {
		t.Fatal(err)
	}
	if rawPath != "/api/v1/customer/products/my%20prod/releases/2.4.1+build.5%2Fx" {
		t.Fatalf("path %q", rawPath)
	}
	if m.Version != "2.4.1+build.5/x" || len(m.Images) != 1 || m.Images[0].RepositoryPath != "v/app" {
		t.Fatalf("manifest %+v", m)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil || back["format"].(float64) != 1 {
		t.Fatalf("raw %s", raw)
	}
}

func fileFor(body string, srvURL string) ManifestFile {
	sum := sha256.Sum256([]byte(body))
	return ManifestFile{Name: "values.yaml", Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:]), URL: srvURL + "/api/v1/customer/products/p/releases/1/files/values.yaml"}
}

func TestDownloadFile(t *testing.T) {
	body := "hello world"
	var user, ua string
	c, srv := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _, _ = r.BasicAuth()
		ua = r.UserAgent()
		io.WriteString(w, body)
	}))
	var sb strings.Builder
	if err := c.DownloadFile(context.Background(), fileFor(body, srv.URL), &sb); err != nil {
		t.Fatal(err)
	}
	if sb.String() != body || user != "ctok_abc" || ua != "breakwater-cli/dev" {
		t.Fatalf("body %q user %q ua %q", sb.String(), user, ua)
	}
}

func TestDownloadFileErrors(t *testing.T) {
	body := "hello world"
	t.Run("sha mismatch", func(t *testing.T) {
		c, srv := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "HELLO WORLD") }))
		err := c.DownloadFile(context.Background(), fileFor(body, srv.URL), io.Discard)
		if err == nil || !strings.Contains(err.Error(), "sha256") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		c, srv := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body+strings.Repeat("x", 1000)) }))
		var n countWriter
		err := c.DownloadFile(context.Background(), fileFor(body, srv.URL), &n)
		if err == nil || !strings.Contains(err.Error(), "expected 11") || n > 12 {
			t.Fatalf("err %v wrote %d", err, n)
		}
	})
	t.Run("short", func(t *testing.T) {
		c, srv := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hi") }))
		if err := c.DownloadFile(context.Background(), fileFor(body, srv.URL), io.Discard); err == nil {
			t.Fatal("want error")
		}
	})
	t.Run("bad name", func(t *testing.T) {
		c, srv := newClient(t, serveJSON(nil))
		f := fileFor(body, srv.URL)
		for _, name := range []string{"../x", "a/b", "", strings.Repeat("a", 101), "a b"} {
			f.Name = name
			if err := c.DownloadFile(context.Background(), f, io.Discard); err == nil {
				t.Fatalf("name %q accepted", name)
			}
		}
	})
	t.Run("redirect", func(t *testing.T) {
		var hits atomic.Int32
		other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
		defer other.Close()
		c, srv := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, 302) }))
		if err := c.DownloadFile(context.Background(), fileFor(body, srv.URL), io.Discard); err == nil || hits.Load() != 0 {
			t.Fatalf("err %v hits %d", err, hits.Load())
		}
	})
}

type countWriter int

func (c *countWriter) Write(p []byte) (int, error) { *c += countWriter(len(p)); return len(p), nil }

func TestDownloadFileRefusesOtherOriginsBeforeAnyRequest(t *testing.T) {
	var hits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer other.Close()
	c, srv := newClient(t, serveJSON(nil))
	srvURL, _ := url.Parse(srv.URL)
	f := fileFor("x", other.URL)
	otherURL, _ := url.Parse(other.URL)
	f.URL = other.URL + "/f"

	err := c.DownloadFile(context.Background(), f, io.Discard)
	want := "file values.yaml is served from http://" + otherURL.Hostname() + ":" + otherURL.Port() + ", not http://" + srvURL.Hostname() + ":" + srvURL.Port() + "; refusing to send credentials there"
	if err == nil || err.Error() != want {
		t.Fatalf("err %v\nwant %s", err, want)
	}
	// Same host, other port; other scheme; look-alike host; userinfo.
	for _, u := range []string{
		"http://" + srvURL.Hostname() + ":1/f",
		"https://" + srvURL.Host + "/f",
		"http://" + srvURL.Hostname() + ".evil.example:" + srvURL.Port() + "/f",
		"http://user:pw@" + srvURL.Host + "/f",
		"//" + srvURL.Host + "/f",
		"/f",
	} {
		f.URL = u
		if err := c.DownloadFile(context.Background(), f, io.Discard); err == nil {
			t.Fatalf("%s accepted", u)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("other origin hit %d times", hits.Load())
	}
}

func TestEffectiveOriginDefaultPorts(t *testing.T) {
	a, _ := url.Parse("https://app.example.com")
	b, _ := url.Parse("https://APP.example.com:443/x")
	if originString(a) != originString(b) {
		t.Fatalf("%s vs %s", originString(a), originString(b))
	}
	h, _ := url.Parse("http://app.example.com")
	if originString(h) != "http://app.example.com:80" {
		t.Fatal(originString(h))
	}
}

func TestStartAndCompleteBundle(t *testing.T) {
	var bodies []map[string]any
	var paths, methods []string
	c, _ := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		bodies = append(bodies, b)
		paths = append(paths, r.URL.EscapedPath())
		methods = append(methods, r.Method)
		if r.Method == "POST" {
			w.WriteHeader(201)
			io.WriteString(w, `{"data":{"id":"bnd_123"}}`)
			return
		}
		io.WriteString(w, `{"data":{"id":"bnd_123"}}`)
	}))
	id, err := c.StartBundle(context.Background(), "p", "2.4.1+b", []string{"linux/amd64", "linux/arm64"})
	if err != nil || id != "bnd_123" {
		t.Fatalf("id %q err %v", id, err)
	}
	if err := c.CompleteBundle(context.Background(), id, 12345); err != nil {
		t.Fatal(err)
	}
	if methods[0] != "POST" || paths[0] != "/api/v1/customer/products/p/releases/2.4.1+b/bundles" {
		t.Fatalf("%v %v", methods, paths)
	}
	if methods[1] != "PATCH" || paths[1] != "/api/v1/customer/bundles/bnd_123" {
		t.Fatalf("%v %v", methods, paths)
	}
	wantStart := `{"cli_version":"dev","platforms":["linux/amd64","linux/arm64"]}`
	wantDone := `{"status":"completed","total_bytes":12345}`
	for i, want := range []string{wantStart, wantDone} {
		got, _ := json.Marshal(bodies[i])
		if string(got) != want {
			t.Fatalf("body %d: %s want %s", i, got, want)
		}
	}
}

func TestCompleteBundleConflict(t *testing.T) {
	c, _ := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(409)
		io.WriteString(w, `{"error":"Bundle already completed"}`)
	}))
	err := c.CompleteBundle(context.Background(), "x", 1)
	if err == nil || err.Error() != "Breakwater API returned 409: Bundle already completed" {
		t.Fatal(err)
	}
}
