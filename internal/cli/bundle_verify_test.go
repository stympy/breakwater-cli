package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/stympy/breakwater-cli/internal/api"
	"github.com/stympy/breakwater-cli/internal/bundle"
	"github.com/stympy/breakwater-cli/internal/bundle/bundletest"
)

func verifyFixture(t *testing.T) (string, bundletest.Options) {
	t.Helper()
	img := bundletest.RandomImage(t)
	index := bundletest.PlatformIndex(t, "linux/amd64", "linux/arm64")
	opts := bundletest.Options{
		Images: []bundletest.Image{
			{Reference: "registry.breakwaterapp.com/acme/api:2.4.1", Image: img},
			{Kind: "external", Reference: "docker.io/library/redis:7", Index: index},
		},
		Files: []bundletest.File{{Name: "install.sh", Data: []byte("#!/bin/sh\n")}},
		Bin:   []bundletest.Bin{{Name: "breakwater_linux_amd64", Platform: "linux/amd64", Data: []byte("ELF")}},
	}
	return bundletest.Build(t, opts), opts
}

func TestBundleVerifyGood(t *testing.T) {
	path, _ := verifyFixture(t)
	ios, out, errb := testIO("", nil)
	if code := execute(ios, []string{"bundle", "verify", path}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	got := out.String()
	for _, want := range []string{
		"Vendor:       Acme (acme)\n",
		"Product:      API Server (api)\n",
		"Version:      2.4.1\n",
		"Created:      2026-10-30T12:00:00Z\n",
		"CLI version:  0.1.0\n",
		"Platforms:    all\n",
		"Images (2):\n  registry.breakwaterapp.com/acme/api:2.4.1@sha256:",
		"  1 platform   ",
		"  docker.io/library/redis:7@sha256:",
		"  2 platforms  ",
		"Files (1):\n  install.sh  10 B\n",
		"Binaries (1):\n  breakwater_linux_amd64  linux/amd64  3 B\n",
		"\nOK: every entry matches the digests recorded in bundle.json.\n",
		"Bundle SHA-256: " + fileSHA256(t, path) + "\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// Full image digests, for comparing with the release page.
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "@sha256:") {
			ref := strings.Fields(line)[0]
			if hex := ref[strings.Index(ref, "@sha256:")+8:]; len(hex) != 64 {
				t.Errorf("digest not in full: %q", ref)
			}
		}
	}
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestBundleVerifyPlatforms(t *testing.T) {
	_, opts := verifyFixture(t)
	im, _ := opts.Images[1].Index.IndexManifest()
	opts.Platforms = []string{"linux/arm64"}
	opts.Images[1].Children = append(opts.Images[1].Children, im.Manifests[1].Digest)
	path := bundletest.Build(t, opts)
	ios, out, errb := testIO("", nil)
	if code := execute(ios, []string{"bundle", "verify", path}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if !strings.Contains(out.String(), "Platforms:    linux/arm64\n") {
		t.Fatalf("out %s", out)
	}
}

func TestBundleVerifyBad(t *testing.T) {
	path, _ := verifyFixture(t)
	bad := bundletest.Corrupt(t, path, "files/install.sh")
	ios, out, errb := testIO("", nil)
	if code := execute(ios, []string{"bundle", "verify", bad}); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout %q", out)
	}
	if want := "breakwater: " + bad + `: entry "files/install.sh" doesn't match its sha256`; !strings.HasPrefix(errb.String(), want) {
		t.Fatalf("stderr %q; want prefix %q", errb, want)
	}
}

func TestBundleVerifyNeedsOneArg(t *testing.T) {
	ios, _, errb := testIO("", nil)
	if code := execute(ios, []string{"bundle", "verify"}); code != 1 || !strings.Contains(errb.String(), "accepts 1 arg") {
		t.Fatalf("exit %d: %s", code, errb)
	}
}

func TestBundleVerifyStripsControlCharacters(t *testing.T) {
	_, opts := verifyFixture(t)
	opts.EditManifest = func(m *api.Manifest) {
		m.Vendor.Name = "Acme\x1b]0;pwned\x07"
		m.Product.Name = "API\u202eServer"
	}
	path := bundletest.Build(t, opts)
	ios, out, errb := testIO("", nil)
	if code := execute(ios, []string{"bundle", "verify", path}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if !strings.Contains(out.String(), "Vendor:       Acme]0;pwned (acme)\n") || !strings.Contains(out.String(), "Product:      APIServer (api)\n") {
		t.Fatalf("out %q", out)
	}

	// Errors are cleaned too, newlines and tabs included.
	opts.EditManifest = func(m *api.Manifest) { m.Images[0].Tag = "2.4.1\n\t\x1b[2Jevil" }
	opts.EditHeader = func(h *bundle.Header) { h.Images[0].Tag = "other" }
	path = bundletest.Build(t, opts)
	ios, _, errb = testIO("", nil)
	if code := execute(ios, []string{"bundle", "verify", path}); code != 1 {
		t.Fatalf("exit %d", code)
	}
	msg := strings.TrimSuffix(errb.String(), "\n")
	if strings.ContainsAny(msg, "\x1b\n\t") || !strings.Contains(msg, "(tag 2.4.1[2Jevil)") {
		t.Fatalf("stderr %q", errb)
	}
}
