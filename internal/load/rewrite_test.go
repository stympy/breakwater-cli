package load

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/stympy/breakwater-cli/internal/bundle"
	"github.com/stympy/breakwater-cli/internal/bundle/bundletest"
)

var (
	dAPI    = "sha256:" + strings.Repeat("a", 64)
	dAPINew = "sha256:" + strings.Repeat("b", 64)
	dPG     = "sha256:" + strings.Repeat("c", 64)
)

const compose = "services:\n" +
	"  api:\n" +
	"    image: registry.breakwaterapp.com/acme/api:2.4.1\n" +
	"  db:\n" +
	"    image: \"postgres:16.4\"  # pinned major\n" +
	"  worker:\n" +
	"    image: 'registry.breakwaterapp.com/acme/api@sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "'\r\n" +
	"  pinned:\n" +
	"    image: registry.breakwaterapp.com/acme/api:2.4.1@sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + " # digest\n" +
	"  other:\n" +
	"    image: nginx:1.27\n" +
	"  interpolated:\n" +
	"    image: ${REGISTRY}/acme/api:2.4.1\n" +
	"  # image: postgres:16.4\n" +
	"    environment:\n" +
	"      image: postgres:16.4\n"

const values = "images:\n" +
	"  - image: postgres:16.4\n" +
	"  -   image:   docker.io/library/postgres:16.4\n"

func rewriteBundle(t *testing.T) *bundle.Bundle {
	t.Helper()
	b, _ := openBundle(t, bundletest.Options{
		Images: []bundletest.Image{{Image: bundletest.RandomImage(t)}},
		Files: []bundletest.File{
			{Name: "compose.yaml", Data: []byte(compose)},
			{Name: "values.yaml", Data: []byte(values)},
			{Name: "notes.yml", Data: []byte("no images here\n")},
			{Name: "install.sh", Data: []byte("image: postgres:16.4\n")},
		},
	})
	return b
}

var registryMappings = []Mapping{
	{From: "registry.breakwaterapp.com/acme/api:2.4.1", To: "reg.local/acme/api:2.4.1", FromDigest: dAPI, ToDigest: dAPINew},
	{From: "docker.io/library/postgres:16.4", To: "reg.local/docker.io/library/postgres:16.4", FromDigest: dPG, ToDigest: dPG},
}

var dockerMappings = []Mapping{
	{From: "registry.breakwaterapp.com/acme/api:2.4.1", To: "registry.breakwaterapp.com/acme/api:2.4.1", FromDigest: dAPI, ToDigest: dAPINew},
	{From: "postgres:16.4", To: "docker.io/library/postgres:16.4", FromDigest: dPG, ToDigest: "sha256:" + strings.Repeat("d", 64)},
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestRewriteFilesForRegistry(t *testing.T) {
	b := rewriteBundle(t)
	dir := filepath.Join(t.TempDir(), "deploy", "files")
	written, err := RewriteFiles(b, dir, registryMappings, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(dir, "compose.yaml"), filepath.Join(dir, "values.yaml")}
	if !slices.Equal(written, want) {
		t.Fatalf("wrote %q, want %q", written, want)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Fatalf("dir: %v %v", fi, err)
	}
	wantCompose := "services:\n" +
		"  api:\n" +
		"    image: reg.local/acme/api:2.4.1\n" +
		"  db:\n" +
		"    image: \"reg.local/docker.io/library/postgres:16.4\"  # pinned major\n" +
		"  worker:\n" +
		"    image: 'reg.local/acme/api:2.4.1@" + dAPINew + "'\r\n" +
		"  pinned:\n" +
		"    image: reg.local/acme/api:2.4.1@" + dAPINew + " # digest\n" +
		"  other:\n" +
		"    image: nginx:1.27\n" +
		"  interpolated:\n" +
		"    image: ${REGISTRY}/acme/api:2.4.1\n" +
		"  # image: postgres:16.4\n" +
		"    environment:\n" +
		"      image: reg.local/docker.io/library/postgres:16.4\n"
	if got := readFile(t, want[0]); got != wantCompose {
		t.Fatalf("compose.yaml:\n%s\nwant:\n%s", got, wantCompose)
	}
	wantValues := "images:\n" +
		"  - image: reg.local/docker.io/library/postgres:16.4\n" +
		"  -   image:   reg.local/docker.io/library/postgres:16.4\n"
	if got := readFile(t, want[1]); got != wantValues {
		t.Fatalf("values.yaml:\n%s", got)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatalf("dir has %d entries", len(entries))
	}
}

func TestRewriteFilesForDockerDropsDigests(t *testing.T) {
	b := rewriteBundle(t)
	dir := t.TempDir()
	if _, err := RewriteFiles(b, dir, dockerMappings, false); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, filepath.Join(dir, "compose.yaml"))
	for _, want := range []string{
		"    image: registry.breakwaterapp.com/acme/api:2.4.1\n",
		"    image: \"docker.io/library/postgres:16.4\"  # pinned major\n",
		"    image: 'registry.breakwaterapp.com/acme/api:2.4.1'\r\n",
		"    image: registry.breakwaterapp.com/acme/api:2.4.1 # digest\n",
		"    image: nginx:1.27\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("compose.yaml lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "@sha256") {
		t.Fatalf("a digest survived:\n%s", got)
	}
}

func TestRewriteFilesUnmatchedDigestIsLeftAlone(t *testing.T) {
	b, _ := openBundle(t, bundletest.Options{
		Images: []bundletest.Image{{Image: bundletest.RandomImage(t)}},
		Files:  []bundletest.File{{Name: "compose.yml", Data: []byte("image: registry.breakwaterapp.com/acme/api:2.4.1@sha256:" + strings.Repeat("e", 64) + "\n")}},
	})
	dir := t.TempDir()
	if _, err := RewriteFiles(b, dir, registryMappings, true); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(dir, "compose.yml")); !strings.Contains(got, strings.Repeat("e", 64)) || strings.Contains(got, "reg.local") {
		t.Fatalf("got %q", got)
	}
}

func TestRewriteFilesRefusesAnExistingFile(t *testing.T) {
	b := rewriteBundle(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "values.yaml"), []byte("mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := CheckRewrite(b, dir); err == nil || !strings.Contains(err.Error(), "values.yaml") {
		t.Fatalf("CheckRewrite: %v", err)
	}
	_, err := RewriteFiles(b, dir, registryMappings, true)
	if err == nil || !strings.Contains(err.Error(), "values.yaml") || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("err = %v", err)
	}
	if got := readFile(t, filepath.Join(dir, "values.yaml")); got != "mine\n" {
		t.Fatalf("overwrote: %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "compose.yaml")); !os.IsNotExist(err) {
		t.Fatal("wrote compose.yaml after finding a conflict")
	}
}

func TestRewriteFilesStayInTheDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	b := rewriteBundle(t)
	dir, outside := t.TempDir(), t.TempDir()
	victim := filepath.Join(outside, "victim.yaml")
	if err := os.Symlink(victim, filepath.Join(dir, "compose.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := RewriteFiles(b, dir, registryMappings, true); err == nil {
		t.Fatal("wrote through a symlink")
	}
	if _, err := os.Stat(victim); !os.IsNotExist(err) {
		t.Fatal("wrote outside the dir")
	}

	// A dangling symlink to a directory outside: O_EXCL refuses it.
	dir2 := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "values.yaml"), filepath.Join(dir2, "values.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := RewriteFiles(b, dir2, registryMappings, true); err == nil {
		t.Fatal("wrote through a dangling symlink")
	}
	if _, err := os.Stat(filepath.Join(outside, "values.yaml")); !os.IsNotExist(err) {
		t.Fatal("wrote outside the dir")
	}
}

func TestRewriteFilesNothingToRewrite(t *testing.T) {
	b, _ := openBundle(t, bundletest.Options{
		Images: []bundletest.Image{{Image: bundletest.RandomImage(t)}},
		Files:  []bundletest.File{{Name: "README.txt", Data: []byte("image: x\n")}},
	})
	dir := filepath.Join(t.TempDir(), "out")
	written, err := RewriteFiles(b, dir, registryMappings, true)
	if err != nil || len(written) != 0 {
		t.Fatalf("wrote %q, err %v", written, err)
	}
}

func TestRewriteLine(t *testing.T) {
	l := newLookup(registryMappings)
	for in, want := range map[string]string{
		"image: postgres:16.4":                    "image: reg.local/docker.io/library/postgres:16.4",
		"image: postgres":                         "image: postgres",
		"image: \"postgres:16.4":                  "image: \"reg.local/docker.io/library/postgres:16.4",
		"imagex: postgres:16.4":                   "imagex: postgres:16.4",
		"  - image:\tpostgres:16.4 #c":            "  - image:\treg.local/docker.io/library/postgres:16.4 #c",
		"image: postgres:16.4@" + dPG:             "image: reg.local/docker.io/library/postgres:16.4@" + dPG,
		"image: postgres:16.4@sha256:nothex":      "image: postgres:16.4@sha256:nothex",
		"image: UPPER/case:1":                     "image: UPPER/case:1",
		"image: registry.breakwaterapp.com/acme/": "image: registry.breakwaterapp.com/acme/",
	} {
		if got := l.rewriteLine(in, true); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}
