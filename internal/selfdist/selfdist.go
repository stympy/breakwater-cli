// Package selfdist finds breakwater binaries to carry in a bundle: the
// running one, and on request released ones for other platforms from
// GitHub, checked against the release's checksums.txt.
package selfdist

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/stympy/breakwater-cli/internal/version"
)

// MaxBinarySize caps a downloaded binary.
const MaxBinarySize = 256 << 20

// maxChecksumsSize caps checksums.txt.
const maxChecksumsSize = 1 << 20

// Platforms are the platforms breakwater is released for.
var Platforms = []string{"linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64", "windows/arm64"}

// Binary is a breakwater binary on disk, named as it goes in a bundle.
type Binary struct {
	Name     string // breakwater_<os>_<arch>[.exe]
	Platform string // <os>/<arch>
	Path     string
	Size     int64
	SHA256   string // plain hex
}

// binaryName is breakwater_<os>_<arch>, with .exe on Windows.
func binaryName(goos, goarch string) string {
	n := "breakwater_" + goos + "_" + goarch
	if goos == "windows" {
		n += ".exe"
	}
	return n
}

// Running is the running executable.
func Running() (Binary, error) {
	path, err := os.Executable()
	if err != nil {
		return Binary{}, fmt.Errorf("finding the running breakwater binary: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return Binary{}, fmt.Errorf("reading the running breakwater binary: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return Binary{}, fmt.Errorf("reading the running breakwater binary: %w", err)
	}
	return Binary{
		Name:     binaryName(runtime.GOOS, runtime.GOARCH),
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
		Path:     path,
		Size:     n,
		SHA256:   hex.EncodeToString(h.Sum(nil)),
	}, nil
}

func releaseURL(version string) string {
	return "https://github.com/stympy/breakwater-cli/releases/download/v" + version
}

var checksumLine = regexp.MustCompile(`^([a-f0-9]{64})\s+\*?(\S+)$`)

// Check reports whether Download can fetch platforms for version, without
// any network: version isn't a dev build and every platform is released.
func Check(version string, platforms []string) error {
	if version == "dev" {
		return errors.New("--cli-binaries needs a released breakwater; this is a dev build")
	}
	for _, p := range platforms {
		if !slices.Contains(Platforms, p) {
			return fmt.Errorf("--cli-binaries: breakwater isn't released for %q (it is for %s)", p, strings.Join(Platforms, ", "))
		}
	}
	return nil
}

// Download fetches the released breakwater binaries for platforms (except
// the running platform, which the caller adds with Running) into temporary
// files, checked against the release's checksums.txt. baseURL defaults to
// the GitHub release of version. The caller removes the files (Remove).
// No credentials are sent.
func Download(ctx context.Context, version string, platforms []string, client *http.Client, baseURL string) ([]Binary, error) {
	if err := Check(version, platforms); err != nil {
		return nil, err
	}
	if client == nil {
		client = http.DefaultClient
	}
	if baseURL == "" {
		baseURL = releaseURL(version)
	}
	baseURL = strings.TrimSuffix(baseURL, "/")
	running := runtime.GOOS + "/" + runtime.GOARCH

	var want []string
	for _, p := range platforms {
		if p != running && !slices.Contains(want, p) {
			want = append(want, p)
		}
	}
	if len(want) == 0 {
		return nil, nil
	}

	var buf bytes.Buffer
	if err := get(ctx, client, baseURL+"/checksums.txt", &buf, maxChecksumsSize); err != nil {
		return nil, fmt.Errorf("fetching checksums.txt of breakwater %s: %w", version, err)
	}
	sums := map[string]string{}
	sc := bufio.NewScanner(&buf)
	for sc.Scan() {
		if m := checksumLine.FindStringSubmatch(strings.TrimSpace(sc.Text())); m != nil {
			sums[m[2]] = m[1]
		}
	}

	var bins []Binary
	for _, p := range want {
		goos, goarch, _ := strings.Cut(p, "/")
		asset := fmt.Sprintf("breakwater_%s_%s_%s", version, goos, goarch)
		if goos == "windows" {
			asset += ".exe"
		}
		sum, ok := sums[asset]
		if !ok {
			Remove(bins)
			return nil, fmt.Errorf("checksums.txt of breakwater %s doesn't list %s", version, asset)
		}
		b, err := download(ctx, client, baseURL+"/"+asset, asset, sum)
		if err != nil {
			Remove(bins)
			return nil, err
		}
		b.Name, b.Platform = binaryName(goos, goarch), p
		bins = append(bins, b)
	}
	return bins, nil
}

func download(ctx context.Context, client *http.Client, url, asset, want string) (Binary, error) {
	f, err := os.CreateTemp("", "breakwater-bin-*")
	if err != nil {
		return Binary{}, err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(f.Name())
		}
	}()
	h := sha256.New()
	cw := &countWriter{}
	if err := get(ctx, client, url, io.MultiWriter(f, h, cw), MaxBinarySize); err != nil {
		return Binary{}, fmt.Errorf("downloading %s: %w", asset, err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return Binary{}, fmt.Errorf("%s has sha256 %s, but its checksum in checksums.txt is %s", asset, got, want)
	}
	if err := f.Close(); err != nil {
		return Binary{}, err
	}
	ok = true
	return Binary{Path: f.Name(), Size: cw.n, SHA256: got}, nil
}

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

// get copies a URL's body to w, refusing more than max bytes.
func get(ctx context.Context, client *http.Client, url string, w io.Writer, max int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", version.UserAgent())
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %s", url, resp.Status)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, max+1))
	if err != nil {
		return err
	}
	if n > max {
		return fmt.Errorf("%s is over the %d byte limit", url, max)
	}
	return nil
}

// Remove deletes downloaded binaries' temporary files.
func Remove(bins []Binary) {
	for _, b := range bins {
		os.Remove(b.Path)
	}
}
