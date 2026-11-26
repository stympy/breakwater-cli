package cli

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const vendorToken = "vapi_test"

var vendorEnv = map[string]string{"BREAKWATER_API_TOKEN": vendorToken}

type fakeVendorAPI struct {
	srv       *httptest.Server
	posted    map[string]any
	postPath  string
	createErr string // problem body to answer the create with
	createSt  int
	createOK  string // body to answer a successful create with (default: a release)
	repoCalls int
}

func newFakeVendorAPI(t *testing.T) *fakeVendorAPI {
	t.Helper()
	f := &fakeVendorAPI{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+vendorToken {
			w.WriteHeader(401)
			w.Write([]byte(`{"title":"Invalid token","status":401,"detail":"The token is invalid.","code":"invalid_token"}`))
			return
		}
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/v1/vendor/repositories":
			f.repoCalls++
			w.Write([]byte(`{"data":[{"id":"repo_1","name":"api","full_path":"acme/api"},{"id":"repo_2","name":"worker","full_path":"acme/worker"}],"meta":{"total_pages":1}}`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/releases"):
			f.postPath = r.URL.Path
			if f.createErr != "" {
				w.WriteHeader(f.createSt)
				w.Write([]byte(f.createErr))
				return
			}
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			f.posted = body
			w.WriteHeader(201)
			if f.createOK != "" {
				w.Write([]byte(f.createOK))
				return
			}
			w.Write([]byte(`{"data":{"id":"rel_1","product_id":"prod_1","version":"2.4.1+b.5","status":"published","images":[{"reference":"r/api:1"}],"files":[{"name":"a.txt","size":2}]}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func TestVendorReleaseCreate(t *testing.T) {
	f := newFakeVendorAPI(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hi"), 0o600)
	os.WriteFile(filepath.Join(dir, "notes.md"), []byte("# Notes\n"), 0o600)
	ios, out, errb := testIO("", vendorEnv)
	code := execute(ios, []string{"vendor", "releases", "create", "prod_1", "2.4.1+b.5", "--host", f.srv.URL,
		"--notes-file", filepath.Join(dir, "notes.md"),
		"--image", "api:1.0", "--image", "repo_2:2.0", "--external-image", "postgres:16.4",
		"--file", filepath.Join(dir, "a.txt"), "--file", filepath.Join(dir, "a.txt") + "=renamed.txt"})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if f.postPath != "/api/v1/vendor/products/prod_1/releases" {
		t.Fatalf("path %q", f.postPath)
	}
	rel := f.posted["release"].(map[string]any)
	if rel["version"] != "2.4.1+b.5" || rel["notes"] != "# Notes\n" {
		t.Fatalf("release %v", rel)
	}
	imgs := rel["images"].([]any)
	want := []map[string]string{{"repository_id": "repo_1", "tag": "1.0"}, {"repository_id": "repo_2", "tag": "2.0"}, {"external": "postgres:16.4"}}
	for i, w := range want {
		got := imgs[i].(map[string]any)
		if len(got) != len(w) {
			t.Fatalf("image %d: %v", i, got)
		}
		for k, v := range w {
			if got[k] != v {
				t.Fatalf("image %d: %v", i, got)
			}
		}
	}
	files := rel["files"].([]any)
	f0, f1 := files[0].(map[string]any), files[1].(map[string]any)
	if f0["name"] != "a.txt" || f1["name"] != "renamed.txt" || f0["content_base64"] != base64.StdEncoding.EncodeToString([]byte("hi")) {
		t.Fatalf("files %v", files)
	}
	wantOut := "Published prod_1 2.4.1+b.5 (1 images, 1 files)\n" + f.srv.URL + "/vendor/products/prod_1/releases/2.4.1+b.5\n"
	if out.String() != wantOut {
		t.Fatalf("out %q", out)
	}
}

func TestVendorReleaseCreateJSON(t *testing.T) {
	f := newFakeVendorAPI(t)
	ios, out, errb := testIO("", vendorEnv)
	if code := execute(ios, []string{"vendor", "releases", "create", "prod_1", "1", "--host", f.srv.URL, "--json", "--notes", "hello"}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if got["id"] != "rel_1" || got["status"] != "published" || got["url"] != f.srv.URL+"/vendor/products/prod_1/releases/2.4.1+b.5" {
		t.Fatalf("got %v", got)
	}
	if f.repoCalls != 0 {
		t.Fatal("listed repositories without --image")
	}
}

func TestVendorReleaseCreateNotesFromStdin(t *testing.T) {
	f := newFakeVendorAPI(t)
	ios, _, errb := testIO("from stdin", vendorEnv)
	if code := execute(ios, []string{"vendor", "releases", "create", "p", "1", "--host", f.srv.URL, "--notes-file", "-"}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if f.posted["release"].(map[string]any)["notes"] != "from stdin" {
		t.Fatalf("%v", f.posted)
	}
}

func TestVendorReleaseCreateTokenFlagOverridesEnv(t *testing.T) {
	f := newFakeVendorAPI(t)
	ios, _, errb := testIO("", map[string]string{"BREAKWATER_API_TOKEN": "vapi_wrong"})
	if code := execute(ios, []string{"vendor", "releases", "create", "p", "1", "--host", f.srv.URL, "--token", vendorToken}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
}

func TestVendorReleaseCreateAPIErrors(t *testing.T) {
	cases := []struct {
		name, body string
		status     int
		want       []string
	}{
		{"scope", `{"title":"Insufficient scope","status":403,"detail":"This needs a token with the write scope.","code":"insufficient_scope","required_scope":"write"}`, 403,
			[]string{"Insufficient scope: This needs a token with the write scope."}},
		{"validation", `{"title":"Validation failed","status":422,"detail":"Version has already been taken.","code":"validation_failed","errors":[{"field":"version","detail":"has already been taken"}]}`, 422,
			[]string{"Validation failed: Version has already been taken."}},
		{"plain", `Bad Gateway`, 502, []string{"Breakwater API returned 502: Bad Gateway"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeVendorAPI(t)
			f.createErr, f.createSt = c.body, c.status
			ios, out, errb := testIO("", vendorEnv)
			if code := execute(ios, []string{"vendor", "releases", "create", "p", "1", "--host", f.srv.URL}); code != 1 {
				t.Fatalf("exit %d", code)
			}
			if out.Len() != 0 {
				t.Fatalf("stdout %q", out)
			}
			for _, w := range c.want {
				if !strings.Contains(errb.String(), w) {
					t.Fatalf("stderr %q lacks %q", errb, w)
				}
			}
		})
	}
}

func TestVendorReleaseCreateBadToken(t *testing.T) {
	f := newFakeVendorAPI(t)
	ios, _, errb := testIO("", map[string]string{"BREAKWATER_API_TOKEN": "vapi_nope"})
	if code := execute(ios, []string{"vendor", "releases", "create", "p", "1", "--host", f.srv.URL}); code != 1 {
		t.Fatal(code)
	}
	if !strings.Contains(errb.String(), "Invalid token: The token is invalid.") {
		t.Fatalf("stderr %q", errb)
	}
}

func TestVendorReleaseCreateInputErrors(t *testing.T) {
	f := newFakeVendorAPI(t)
	base := []string{"vendor", "releases", "create", "p", "1", "--host", f.srv.URL}
	cases := []struct {
		name string
		env  map[string]string
		args []string
		want string
	}{
		{"no token", nil, nil, "no API token"},
		{"registry token", map[string]string{"BREAKWATER_API_TOKEN": "ctok_x"}, nil, "must be a vapi_ token"},
		{"both notes", vendorEnv, []string{"--notes", "a", "--notes-file", "b"}, "not both"},
		{"unknown repo", vendorEnv, []string{"--image", "nope:1"}, `no repository with id or name "nope"`},
		{"image without tag", vendorEnv, []string{"--image", "api"}, "<repository id or name>:<tag>"},
		{"missing file", vendorEnv, []string{"--file", "/nonexistent/x"}, "reading --file"},
		{"empty file name", vendorEnv, []string{"--file", "x="}, "name after = is empty"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ios, _, errb := testIO("", c.env)
			if code := execute(ios, append(append([]string{}, base...), c.args...)); code != 1 {
				t.Fatalf("exit %d", code)
			}
			if !strings.Contains(errb.String(), c.want) {
				t.Fatalf("stderr %q lacks %q", errb, c.want)
			}
			if f.posted != nil {
				t.Fatal("created a release despite the error")
			}
		})
	}
}

func TestVendorNeverSendsCustomerCredentials(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(201)
		w.Write([]byte(`{"data":{"version":"1","files":[],"images":[]}}`))
	}))
	defer srv.Close()
	env := map[string]string{"BREAKWATER_API_TOKEN": vendorToken, "BREAKWATER_USERNAME": "ctok_x", "BREAKWATER_TOKEN": "secret"}
	ios, _, errb := testIO("", env)
	if code := execute(ios, []string{"vendor", "releases", "create", "p", "1", "--host", srv.URL}); code != 0 {
		t.Fatalf("%d %s", code, errb)
	}
	if gotAuth != "Bearer "+vendorToken {
		t.Fatalf("auth %q", gotAuth)
	}
}

func TestVendorDoesNotFollowRedirects(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("followed the redirect with the token")
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer srv.Close()
	ios, _, errb := testIO("", vendorEnv)
	if code := execute(ios, []string{"vendor", "releases", "create", "p", "1", "--host", srv.URL}); code != 1 {
		t.Fatal(code)
	}
	if !strings.Contains(errb.String(), "refusing to follow") {
		t.Fatalf("stderr %q", errb)
	}
}

func TestVendorReleaseCreateRejectsNonObjectData(t *testing.T) {
	for _, body := range []string{`{"data":null}`, `{}`, `{"data":[]}`, `{"data":"x"}`} {
		for _, asJSON := range []bool{false, true} {
			f := newFakeVendorAPI(t)
			f.createOK = body
			ios, _, errb := testIO("", vendorEnv)
			args := []string{"vendor", "releases", "create", "prod_1", "1", "--host", f.srv.URL, "--notes", "n"}
			if asJSON {
				args = append(args, "--json")
			}
			if code := execute(ios, args); code == 0 || !strings.Contains(errb.String(), "invalid release") {
				t.Fatalf("%s json=%v: exit %d, stderr %q", body, asJSON, code, errb)
			}
		}
	}
}

func TestReadFilesPathWithEquals(t *testing.T) {
	dir := t.TempDir()
	eq := filepath.Join(dir, "app=1.2.tar.gz")
	os.WriteFile(eq, []byte("x"), 0o600)
	got, err := readFiles([]string{eq})
	if err != nil || len(got) != 1 || got[0].Name != "app=1.2.tar.gz" {
		t.Fatalf("existing path with =: %v %v", got, err)
	}
	got, err = readFiles([]string{eq + "=renamed.gz"})
	if err != nil || got[0].Name != "renamed.gz" {
		t.Fatalf("explicit name: %v %v", got, err)
	}
	if _, err := readFiles([]string{filepath.Join(dir, "missing=1.gz")}); err == nil {
		t.Fatal("missing path with = should fail")
	}
}
