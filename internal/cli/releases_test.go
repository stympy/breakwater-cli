package cli

import (
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var testEnv = map[string]string{"BREAKWATER_USERNAME": "ctok_x", "BREAKWATER_TOKEN": "secret"}

func releasesServer(t *testing.T, body string, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, _ := r.BasicAuth(); u != "ctok_x" || p != "secret" {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path != "/api/v1/customer/releases" {
			w.WriteHeader(404)
			return
		}
		if q := r.URL.Query().Get("product"); q != "" && q != "api" {
			body = `{"data":[]}`
		}
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

const twoReleases = `{"data":[
 {"product":{"name":"API Server","slug":"api"},"version":"2.4.1+build.5","published_at":"2026-10-29T23:59:00Z"},
 {"product":{"name":"Worker","slug":"worker"},"version":"1.0.0","published_at":"2026-01-02T00:00:00Z"}]}`

func TestReleasesTable(t *testing.T) {
	srv := releasesServer(t, twoReleases, 200)
	ios, out, errb := testIO("", testEnv)
	if code := execute(ios, []string{"releases", "--host", srv.URL}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("out %q", out)
	}
	if strings.Fields(lines[0])[0] != "PRODUCT" || strings.Join(strings.Fields(lines[0]), " ") != "PRODUCT VERSION PUBLISHED" {
		t.Fatalf("header %q", lines[0])
	}
	if strings.Join(strings.Fields(lines[1]), " ") != "api 2.4.1+build.5 2026-10-29" || strings.Join(strings.Fields(lines[2]), " ") != "worker 1.0.0 2026-01-02" {
		t.Fatalf("rows %q", lines)
	}
}

func TestReleasesEmptyAndProduct(t *testing.T) {
	srv := releasesServer(t, twoReleases, 200)
	ios, out, _ := testIO("", testEnv)
	if code := execute(ios, []string{"releases", "--host", srv.URL, "--product", "nope"}); code != 0 {
		t.Fatal(code)
	}
	if out.String() != "No releases available to this token.\n" {
		t.Fatalf("out %q", out)
	}
}

func TestReleasesJSON(t *testing.T) {
	srv := releasesServer(t, twoReleases, 200)
	ios, out, _ := testIO("", testEnv)
	if code := execute(ios, []string{"releases", "--host", srv.URL, "--json"}); code != 0 {
		t.Fatal(code)
	}
	for _, want := range []string{"[\n  {\n    \"product\": {", "\"slug\": \"api\"", "\"version\": \"2.4.1+build.5\"", "\"published_at\": \"2026-10-29T23:59:00Z\""} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in %s", want, out)
		}
	}
	srv3 := releasesServer(t, `{"data":[{"product":{"name":"P","slug":"p"},"version":"1","published_at":null,"future":{"a":1}}]}`, 200)
	ios, out, _ = testIO("", testEnv)
	execute(ios, []string{"releases", "--host", srv3.URL, "--json"})
	if !strings.Contains(out.String(), "\"future\": {\n      \"a\": 1\n    }") {
		t.Fatalf("unknown fields lost: %s", out)
	}
	srv2 := releasesServer(t, `{"data":[]}`, 200)
	ios, out, _ = testIO("", testEnv)
	execute(ios, []string{"releases", "--host", srv2.URL, "--json"})
	if out.String() != "[]\n" {
		t.Fatalf("empty json %q", out)
	}
}

func TestReleasesErrors(t *testing.T) {
	srv := releasesServer(t, `{"error":"plan_required"}`, 403)
	ios, _, errb := testIO("", testEnv)
	if code := execute(ios, []string{"releases", "--host", srv.URL}); code != 1 {
		t.Fatal(code)
	}
	if errb.String() != "breakwater: air-gapped bundles aren't included in this vendor's Breakwater plan\n" {
		t.Fatalf("stderr %q", errb)
	}
	ios, _, errb = testIO("", map[string]string{"BREAKWATER_USERNAME": "ctok_x", "BREAKWATER_TOKEN": "bad"})
	if code := execute(ios, []string{"releases", "--host", srv.URL}); code != 1 || !strings.Contains(errb.String(), "refused the credentials") {
		t.Fatalf("stderr %q", errb)
	}
}

func TestCAFileIsTrustedForTheAPI(t *testing.T) {
	srv := quietTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(twoReleases))
	}))
	ios, _, errb := testIO("", testEnv)
	if code := execute(ios, []string{"releases", "--host", srv.URL}); code != 1 || !strings.Contains(errb.String(), "certificate") {
		t.Fatalf("without --ca-file: exit %d: %s", code, errb)
	}
	ca := writeCA(t, srv)
	ios, out, errb := testIO("", testEnv)
	if code := execute(ios, []string{"releases", "--host", srv.URL, "--ca-file", ca}); code != 0 || !strings.Contains(out.String(), "worker") {
		t.Fatalf("with --ca-file: exit %d: %s", code, errb)
	}
	ios, _, errb = testIO("", testEnv)
	if code := execute(ios, []string{"releases", "--host", srv.URL, "--ca-file", ca + ".missing"}); code != 1 || !strings.Contains(errb.String(), "--ca-file") {
		t.Fatalf("missing --ca-file: exit %d: %s", code, errb)
	}
}

// quietTLSServer is an HTTPS test server that doesn't log the handshake
// errors of clients that don't trust it.
func quietTLSServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// writeCA writes a TLS test server's certificate as a PEM file.
func writeCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
