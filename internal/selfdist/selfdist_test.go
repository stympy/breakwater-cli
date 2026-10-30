package selfdist

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
)

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// otherPlatforms are two supported platforms that aren't the running one.
func otherPlatforms() []string {
	var out []string
	for _, p := range []string{"linux/amd64", "windows/arm64", "darwin/amd64"} {
		if p != runtime.GOOS+"/"+runtime.GOARCH && len(out) < 2 {
			out = append(out, p)
		}
	}
	return out
}

func assetName(version, platform string) string {
	os, arch, _ := strings.Cut(platform, "/")
	n := fmt.Sprintf("breakwater_%s_%s_%s", version, os, arch)
	if os == "windows" {
		n += ".exe"
	}
	return n
}

// fakeGitHub serves checksums.txt and one asset per platform. corrupt names
// an asset served with different bytes than its checksum.
func fakeGitHub(t *testing.T, version string, platforms []string, corrupt string) (*httptest.Server, map[string][]byte, *[]string) {
	t.Helper()
	assets := map[string][]byte{}
	var checksums strings.Builder
	for _, p := range platforms {
		n := assetName(version, p)
		assets[n] = []byte("binary for " + p)
		fmt.Fprintf(&checksums, "%s  %s\n", sum(assets[n]), n)
	}
	fmt.Fprintf(&checksums, "%s  breakwater_%s_linux_amd64.tar.gz\n", sum([]byte("x")), version)
	var agents []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agents = append(agents, r.Header.Get("User-Agent"))
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "checksums.txt" {
			w.Write([]byte(checksums.String()))
			return
		}
		data, ok := assets[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if name == corrupt {
			data = append([]byte("evil "), data...)
		}
		w.Write(data)
	}))
	t.Cleanup(srv.Close)
	return srv, assets, &agents
}

func TestDownloadChecksBinaries(t *testing.T) {
	platforms := otherPlatforms()
	running := runtime.GOOS + "/" + runtime.GOARCH
	srv, assets, agents := fakeGitHub(t, "1.2.3", platforms, "")
	bins, err := Download(context.Background(), "1.2.3", append([]string{running}, platforms...), srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Remove(bins) })
	if len(bins) != len(platforms) {
		t.Fatalf("got %d binaries, want %d (the running platform is skipped)", len(bins), len(platforms))
	}
	for i, b := range bins {
		os_, arch, _ := strings.Cut(platforms[i], "/")
		wantName := "breakwater_" + os_ + "_" + arch
		if os_ == "windows" {
			wantName += ".exe"
		}
		data := assets[assetName("1.2.3", platforms[i])]
		if b.Name != wantName || b.Platform != platforms[i] || b.Size != int64(len(data)) || b.SHA256 != sum(data) {
			t.Fatalf("binary %d: %+v", i, b)
		}
		got, err := os.ReadFile(b.Path)
		if err != nil || string(got) != string(data) {
			t.Fatalf("binary %d at %s: %q, %v", i, b.Path, got, err)
		}
	}
	for _, ua := range *agents {
		if !strings.HasPrefix(ua, "breakwater-cli/") {
			t.Fatalf("User-Agent %q", ua)
		}
	}
}

func TestDownloadRefusesAChecksumMismatch(t *testing.T) {
	platforms := otherPlatforms()
	srv, _, _ := fakeGitHub(t, "1.2.3", platforms, assetName("1.2.3", platforms[1]))
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	bins, err := Download(context.Background(), "1.2.3", platforms, srv.Client(), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		Remove(bins)
		t.Fatalf("got %v", err)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
}

func TestDownloadRefusesDevAndUnknownPlatforms(t *testing.T) {
	srv, _, _ := fakeGitHub(t, "1.2.3", nil, "")
	_, err := Download(context.Background(), "dev", []string{"linux/amd64"}, srv.Client(), srv.URL)
	if err == nil || err.Error() != "--cli-binaries needs a released breakwater; this is a dev build" {
		t.Fatalf("dev: %v", err)
	}
	for _, p := range []string{"plan9/amd64", "linux/386", "linux/arm64/v8", "linux"} {
		_, err := Download(context.Background(), "1.2.3", []string{p}, srv.Client(), srv.URL)
		if err == nil || !strings.Contains(err.Error(), p) {
			t.Fatalf("%s: %v", p, err)
		}
	}
}

func TestDownloadRefusesAMissingChecksum(t *testing.T) {
	srv, _, _ := fakeGitHub(t, "1.2.3", nil, "")
	_, err := Download(context.Background(), "1.2.3", otherPlatforms()[:1], srv.Client(), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "checksums.txt") {
		t.Fatalf("got %v", err)
	}
}

func TestDefaultBaseURL(t *testing.T) {
	if got := releaseURL("1.2.3"); got != "https://github.com/stympy/breakwater-cli/releases/download/v1.2.3" {
		t.Fatal(got)
	}
}

func TestRunningHashesTheExecutable(t *testing.T) {
	b, err := Running()
	if err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	want := "breakwater_" + runtime.GOOS + "_" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		want += ".exe"
	}
	if b.Name != want || b.Platform != runtime.GOOS+"/"+runtime.GOARCH || b.Size != int64(len(data)) || b.SHA256 != sum(data) || b.Path == "" {
		t.Fatalf("got %+v", b)
	}
}
