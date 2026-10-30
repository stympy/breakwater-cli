package load

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/stympy/breakwater-cli/internal/bundle"
	"github.com/stympy/breakwater-cli/internal/bundle/bundletest"
)

// fakeDocker writes a shell script that answers "version" with platform and
// saves what "load" gets on stdin to the returned path. loadExit is the
// exit code of "load".
func fakeDocker(t *testing.T, platform string, loadExit int) (cmd, saved string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake docker is a shell script")
	}
	dir := t.TempDir()
	saved = filepath.Join(dir, "loaded.tar")
	calls := filepath.Join(dir, "calls")
	script := fmt.Sprintf(`#!/bin/sh
echo "$@" >> %q
case "$1" in
version) echo %q ;;
load) cat > %q; echo "Loaded image: whatever"; echo "load failed: bad archive" >&2; exit %d ;;
*) exit 2 ;;
esac
`, calls, platform, saved, loadExit)
	cmd = filepath.Join(dir, "docker")
	if err := os.WriteFile(cmd, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return cmd, saved
}

func dockerCalls(t *testing.T, cmd string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(cmd), "calls"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

func configName(t *testing.T, img v1.Image) v1.Hash {
	t.Helper()
	h, err := img.ConfigName()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func layerDigests(t *testing.T, img v1.Image) []v1.Hash {
	t.Helper()
	ls, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	var out []v1.Hash
	for _, l := range ls {
		out = append(out, digestOf(t, l))
	}
	return out
}

func TestToDocker(t *testing.T) {
	cmd, saved := fakeDocker(t, "linux/amd64", 0)
	amd := bundletest.RandomImage(t)
	index := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: bundletest.RandomImage(t), Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}}},
		mutate.IndexAddendum{Add: amd, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}},
		mutate.IndexAddendum{Add: bundletest.RandomImage(t), Descriptor: v1.Descriptor{
			Platform:    &v1.Platform{OS: "unknown", Architecture: "unknown"},
			Annotations: map[string]string{"vnd.docker.reference.type": "attestation-manifest"},
		}},
	)
	redis := bundletest.RandomImage(t)
	armOnly := bundletest.PlatformIndex(t, "linux/arm64")
	b, _ := openBundle(t, bundletest.Options{Images: []bundletest.Image{
		{Index: index},
		{Kind: "external", Reference: "redis:7", Image: redis},
		{Reference: "registry.breakwaterapp.com/acme/zarf-package:2.4.1", Image: artifact(t)},
		{Reference: "registry.breakwaterapp.com/acme/arm-tool:2.4.1", Index: armOnly},
	}})

	var out bytes.Buffer
	ms, skipped, err := ToDocker(context.Background(), b, cmd, &out)
	if err != nil {
		t.Fatal(err)
	}
	if got := dockerCalls(t, cmd); !slices.Equal(got, []string{"version --format {{.Server.Os}}/{{.Server.Arch}}", "load"}) {
		t.Fatalf("docker calls %q", got)
	}

	for _, tc := range []struct {
		tag  string
		want v1.Image
	}{
		{"registry.breakwaterapp.com/acme/api:2.4.1", amd},
		{"docker.io/library/redis:7", redis},
	} {
		tag, err := name.NewTag(tc.tag)
		if err != nil {
			t.Fatal(err)
		}
		img, err := tarball.ImageFromPath(saved, &tag)
		if err != nil {
			t.Fatalf("%s: %v", tc.tag, err)
		}
		if configName(t, img) != configName(t, tc.want) || !slices.Equal(layerDigests(t, img), layerDigests(t, tc.want)) {
			t.Fatalf("%s isn't the expected image", tc.tag)
		}
		ls, _ := img.Layers()
		for _, l := range ls { // reads and checks every layer in the tar
			if _, err := l.DiffID(); err != nil {
				t.Fatal(err)
			}
		}
	}
	m, err := tarball.LoadManifest(func() (io.ReadCloser, error) { return os.Open(saved) })
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 {
		t.Fatalf("archive has %d images: %+v", len(m), m)
	}

	if len(ms) != 2 || ms[0].To != "registry.breakwaterapp.com/acme/api:2.4.1" || ms[1].To != "docker.io/library/redis:7" {
		t.Fatalf("mappings %+v", ms)
	}
	if ms[0].FromDigest != digestOf(t, index).String() || ms[0].ToDigest != digestOf(t, amd).String() {
		t.Fatalf("mapping %+v", ms[0])
	}
	wantSkipped := []Skipped{
		{Reference: "registry.breakwaterapp.com/acme/zarf-package:2.4.1", Reason: "not a container image (" + zarfConfig + ")"},
		{Reference: "registry.breakwaterapp.com/acme/arm-tool:2.4.1", Reason: "no linux/amd64 manifest in bundle"},
	}
	if !slices.Equal(skipped, wantSkipped) {
		t.Fatalf("skipped %+v", skipped)
	}
	for _, want := range []string{
		"Loaded registry.breakwaterapp.com/acme/api:2.4.1\n",
		"Loaded docker.io/library/redis:7\n",
		"Skipped registry.breakwaterapp.com/acme/zarf-package:2.4.1: not a container image (" + zarfConfig + ")\n",
		"Skipped registry.breakwaterapp.com/acme/arm-tool:2.4.1: no linux/amd64 manifest in bundle\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output %q lacks %q", out.String(), want)
		}
	}
}

func TestToDockerArm64PrefersV8(t *testing.T) {
	cmd, saved := fakeDocker(t, "linux/arm64", 0)
	v8 := bundletest.RandomImage(t)
	index := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: bundletest.RandomImage(t), Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64", Variant: "v9"}}},
		mutate.IndexAddendum{Add: v8, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}}},
	)
	b, _ := openBundle(t, bundletest.Options{Images: []bundletest.Image{{Index: index}}})
	ms, _, err := ToDocker(context.Background(), b, cmd, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || ms[0].ToDigest != digestOf(t, v8).String() {
		t.Fatalf("mappings %+v", ms)
	}
	if _, err := os.Stat(saved); err != nil {
		t.Fatal(err)
	}
}

func TestPickChild(t *testing.T) {
	d := func(p string, attest bool) v1.Descriptor {
		plat, _ := v1.ParsePlatform(p)
		desc := v1.Descriptor{MediaType: "application/vnd.oci.image.manifest.v1+json", Platform: plat, Digest: v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("0", 63) + fmt.Sprint(len(p)%10)}}
		if attest {
			desc.Annotations = map[string]string{"vnd.docker.reference.type": "attestation-manifest"}
		}
		return desc
	}
	for _, tc := range []struct {
		host     string
		children []v1.Descriptor
		want     string // platform, "" for none
	}{
		{"linux/amd64", []v1.Descriptor{d("linux/arm64", false), d("linux/amd64", false)}, "linux/amd64"},
		{"linux/amd64", []v1.Descriptor{d("linux/arm64", false)}, ""},
		{"linux/arm64", []v1.Descriptor{d("linux/arm64", false)}, "linux/arm64"},
		{"linux/arm64", []v1.Descriptor{d("linux/arm64/v9", false), d("linux/arm64/v8", false)}, "linux/arm64/v8"},
		{"linux/arm64", []v1.Descriptor{d("linux/arm64/v9", false)}, "linux/arm64/v9"},
		{"linux/amd64", []v1.Descriptor{d("linux/amd64/v3", false), d("linux/amd64", false)}, "linux/amd64"},
		{"linux/amd64", []v1.Descriptor{d("linux/amd64", true)}, ""},
		{"windows/amd64", []v1.Descriptor{d("linux/amd64", false)}, ""},
	} {
		got, ok := pickChild(tc.children, tc.host)
		if gotP := bundle.PlatformString(got.Platform); (ok && gotP != tc.want) || (!ok && tc.want != "") {
			t.Errorf("%s from %v: got %q (%v), want %q", tc.host, tc.children, gotP, ok, tc.want)
		}
	}
}

func TestToDockerEverythingSkipped(t *testing.T) {
	cmd, saved := fakeDocker(t, "linux/amd64", 0)
	b, _ := openBundle(t, bundletest.Options{Images: []bundletest.Image{
		{Reference: "registry.breakwaterapp.com/acme/zarf-package:2.4.1", Image: artifact(t)},
	}})
	ms, skipped, err := ToDocker(context.Background(), b, cmd, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 0 || len(skipped) != 1 {
		t.Fatalf("mappings %+v, skipped %+v", ms, skipped)
	}
	if slices.Contains(dockerCalls(t, cmd), "load") {
		t.Fatal("ran docker load with nothing to load")
	}
	if _, err := os.Stat(saved); !os.IsNotExist(err) {
		t.Fatal("docker load got an archive")
	}
}

func TestToDockerLoadFailure(t *testing.T) {
	cmd, _ := fakeDocker(t, "linux/amd64", 1)
	b, _ := openBundle(t, bundletest.Options{Images: []bundletest.Image{{Image: bundletest.RandomImage(t)}}})
	_, _, err := ToDocker(context.Background(), b, cmd, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "docker load failed") || !strings.Contains(err.Error(), "load failed: bad archive") {
		t.Fatalf("err = %v", err)
	}
}

func TestToDockerBadVersionOutput(t *testing.T) {
	cmd, _ := fakeDocker(t, "\x1b[31mnonsense", 0)
	b, _ := openBundle(t, bundletest.Options{Images: []bundletest.Image{{Image: bundletest.RandomImage(t)}}})
	_, _, err := ToDocker(context.Background(), b, cmd, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "platform") {
		t.Fatalf("err = %v", err)
	}
	if _, _, err := ToDocker(context.Background(), b, filepath.Join(t.TempDir(), "nope"), &bytes.Buffer{}); err == nil {
		t.Fatal("a missing docker command worked")
	}
}

func TestToDockerFailsWhenABlobChangesAfterOpen(t *testing.T) {
	cmd, _ := fakeDocker(t, "linux/amd64", 0)
	img := bundletest.RandomImage(t)
	b, path := openBundle(t, bundletest.Options{Images: []bundletest.Image{{Image: img}}})
	layers, _ := img.Layers()
	p, _ := bundle.BlobPath(digestOf(t, layers[0]).String())
	bundletest.FlipByte(t, path, p)

	_, _, err := ToDocker(context.Background(), b, cmd, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "changed after it was verified") {
		t.Fatalf("err = %v", err)
	}
}

func TestToDockerRefusesTwoImagesUnderOneName(t *testing.T) {
	cmd, _ := fakeDocker(t, "linux/amd64", 0)
	b, _ := openBundle(t, bundletest.Options{Images: []bundletest.Image{
		{Kind: "external", Reference: "redis:7", Image: bundletest.RandomImage(t)},
		{Kind: "external", Reference: "docker.io/library/redis:7", Image: bundletest.RandomImage(t)},
	}})
	_, _, err := ToDocker(context.Background(), b, cmd, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "both") {
		t.Fatalf("err = %v", err)
	}
	if slices.Contains(dockerCalls(t, cmd), "load") {
		t.Fatal("ran docker load")
	}
}
