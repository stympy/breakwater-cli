package cli

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stympy/breakwater-cli/internal/bundle"
	"github.com/stympy/breakwater-cli/internal/bundle/bundletest"
)

// loadRegistry is an in-memory registry that counts requests and, with
// user set, wants Basic credentials user/secret.
func loadRegistry(t *testing.T, user string) (string, *atomic.Int64) {
	t.Helper()
	reg := quietRegistry()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		if user != "" {
			if u, p, ok := r.BasicAuth(); !ok || u != user || p != "secret" {
				w.Header().Set("WWW-Authenticate", `Basic realm="target"`)
				w.WriteHeader(401)
				return
			}
		}
		reg.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://"), &n
}

func loadFixture(t *testing.T) (string, v1.Image) {
	t.Helper()
	// No Docker credential store: the target registry is anonymous.
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	img := bundletest.RandomImage(t)
	return bundletest.Build(t, bundletest.Options{
		Images: []bundletest.Image{{Image: img}},
		Files: []bundletest.File{
			{Name: "compose.yaml", Data: []byte("services:\n  api:\n    image: registry.breakwaterapp.com/acme/api:2.4.1\n")},
			{Name: "install.sh", Data: []byte("#!/bin/sh\n")},
		},
	}), img
}

func TestBundleLoadToRegistry(t *testing.T) {
	path, img := loadFixture(t)
	host, _ := loadRegistry(t, "")
	dir := filepath.Join(t.TempDir(), "files")
	ios, out, errb := testIO("", testEnv)
	if code := execute(ios, []string{"bundle", "load", path, "--registry", host + "/mirror", "--insecure", "--rewrite-files", dir}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	d, _ := img.Digest()
	to := host + "/mirror/acme/api:2.4.1"
	if !strings.Contains(out.String(), "registry.breakwaterapp.com/acme/api:2.4.1 -> "+to+"@"+d.String()+"\n") {
		t.Fatalf("stdout %q", out)
	}
	if !strings.Contains(out.String(), "Wrote "+filepath.Join(dir, "compose.yaml")+"\n") {
		t.Fatalf("stdout %q", out)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "compose.yaml"))
	if err != nil || !strings.Contains(string(raw), "image: "+to+"\n") {
		t.Fatalf("compose.yaml %q %v", raw, err)
	}
	ref, _ := name.ParseReference(to, name.Insecure)
	if desc, err := remote.Head(ref); err != nil || desc.Digest != d {
		t.Fatalf("pushed %v %v", desc, err)
	}
}

func TestBundleLoadUsesTheGivenCredentials(t *testing.T) {
	path, _ := loadFixture(t)
	host, _ := loadRegistry(t, "pusher")
	// BREAKWATER_* are Breakwater's credentials and aren't sent to the target.
	ios, _, errb := testIO("", map[string]string{"BREAKWATER_USERNAME": "pusher", "BREAKWATER_TOKEN": "secret"})
	if code := execute(ios, []string{"bundle", "load", path, "--registry", host, "--insecure"}); code != 1 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	ios, out, errb := testIO("secret\n", nil)
	if code := execute(ios, []string{"bundle", "load", path, "--registry", host, "--insecure", "--username", "pusher", "--password-stdin"}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if !strings.Contains(out.String(), " -> "+host+"/acme/api:2.4.1@") {
		t.Fatalf("stdout %q", out)
	}
}

func TestBundleLoadCorruptBundlePushesNothing(t *testing.T) {
	path, img := loadFixture(t)
	layers, _ := img.Layers()
	ld, _ := layers[0].Digest()
	p, _ := bundle.BlobPath(ld.String())
	corrupt := bundletest.Corrupt(t, path, p)
	host, n := loadRegistry(t, "")
	dir := filepath.Join(t.TempDir(), "files")

	ios, out, errb := testIO("", testEnv)
	if code := execute(ios, []string{"bundle", "load", corrupt, "--registry", host, "--insecure", "--rewrite-files", dir}); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "breakwater: "+corrupt+": entry \""+p+"\" doesn't match its sha256") {
		t.Fatalf("stderr %q", errb)
	}
	if n.Load() != 0 {
		t.Fatalf("%d requests reached the registry", n.Load())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout %q", out)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("created the rewrite dir")
	}
}

func TestBundleLoadExistingRewriteFilePushesNothing(t *testing.T) {
	path, _ := loadFixture(t)
	host, n := loadRegistry(t, "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	ios, _, errb := testIO("", testEnv)
	if code := execute(ios, []string{"bundle", "load", path, "--registry", host, "--insecure", "--rewrite-files", dir}); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), filepath.Join(dir, "compose.yaml")+" already exists") || n.Load() != 0 {
		t.Fatalf("stderr %q, %d requests", errb, n.Load())
	}
}

func TestBundleLoadNeedsExactlyOneTarget(t *testing.T) {
	path, _ := loadFixture(t)
	for _, args := range [][]string{
		{"bundle", "load", path},
		{"bundle", "load", path, "--docker", "--registry", "reg.example.com"},
		{"bundle", "load", path, "--registry", ""},
	} {
		ios, _, errb := testIO("", testEnv)
		if code := execute(ios, args); code != 1 {
			t.Fatalf("%v: exit %d", args, code)
		}
		if !strings.Contains(errb.String(), "Usage:") && !strings.Contains(errb.String(), "--registry needs a host") {
			t.Fatalf("%v: stderr %q", args, errb)
		}
	}
	ios, _, errb := testIO("", testEnv)
	if code := execute(ios, []string{"bundle", "load", path}); code != 1 || !strings.Contains(errb.String(), "breakwater: use exactly one of --docker and --registry\n") {
		t.Fatalf("exit %d, stderr %q", code, errb)
	}
}

func cliFakeDocker(t *testing.T, platform string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake docker is a shell script")
	}
	dir := t.TempDir()
	script := fmt.Sprintf("#!/bin/sh\ncase \"$1\" in\nversion) echo %s ;;\nload) cat > %q ;;\nesac\n", platform, filepath.Join(dir, "loaded.tar"))
	cmd := filepath.Join(dir, "docker")
	if err := os.WriteFile(cmd, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return cmd
}

func TestBundleLoadToDocker(t *testing.T) {
	path, _ := loadFixture(t)
	docker := cliFakeDocker(t, "linux/amd64")
	dir := t.TempDir()
	ios, out, errb := testIO("", testEnv)
	if code := execute(ios, []string{"bundle", "load", path, "--docker", "--docker-command", docker, "--rewrite-files", dir}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if !strings.Contains(out.String(), "Loaded registry.breakwaterapp.com/acme/api:2.4.1\n") {
		t.Fatalf("stdout %q", out)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(docker), "loaded.tar")); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "compose.yaml"))
	if !strings.Contains(string(raw), "image: registry.breakwaterapp.com/acme/api:2.4.1\n") {
		t.Fatalf("compose.yaml %q", raw)
	}
}

func TestBundleLoadToDockerAllSkipped(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	path := bundletest.Build(t, bundletest.Options{Images: []bundletest.Image{
		{Index: bundletest.PlatformIndex(t, "linux/arm64")},
	}})
	docker := cliFakeDocker(t, "linux/amd64")
	ios, out, errb := testIO("", testEnv)
	if code := execute(ios, []string{"bundle", "load", path, "--docker", "--docker-command", docker}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if !strings.Contains(out.String(), "Skipped registry.breakwaterapp.com/acme/api:2.4.1: no linux/amd64 manifest in bundle\n") {
		t.Fatalf("stdout %q", out)
	}
	if !strings.Contains(errb.String(), "warning: nothing was loaded") {
		t.Fatalf("stderr %q", errb)
	}
}

func TestBundleLoadChecksTheRegistryBeforeVerifying(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.tar")
	ios, _, errb := testIO("", testEnv)
	if code := execute(ios, []string{"bundle", "load", missing, "--registry", "https://reg.example.com"}); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "without a scheme") || strings.Contains(errb.String(), "Verifying") {
		t.Fatalf("stderr %q", errb)
	}
	// --username without --password-stdin fails before the bundle is read.
	ios, _, errb = testIO("", testEnv)
	if code := execute(ios, []string{"bundle", "load", missing, "--registry", "reg.example.com", "--username", "u"}); code != 1 || !strings.Contains(errb.String(), "--username requires --password-stdin") {
		t.Fatalf("exit %d, stderr %q", code, errb)
	}
}
