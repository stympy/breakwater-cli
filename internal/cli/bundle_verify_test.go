package cli

import (
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
		"\nOK: every image, file and binary matches its digest.\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// digest-short: 12 hex characters after sha256:
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "@sha256:") {
			ref := strings.Fields(line)[0]
			if hex := ref[strings.Index(ref, "@sha256:")+8:]; len(hex) != 12 {
				t.Errorf("short digest %q", ref)
			}
		}
	}
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

	// Errors are cleaned too.
	opts.EditManifest = func(m *api.Manifest) { m.Images[0].Reference = "registry.breakwaterapp.com/acme/\x1b[2Japi:2.4.1" }
	opts.EditHeader = func(h *bundle.Header) { h.Images[0].Tag = "evil" }
	path = bundletest.Build(t, opts)
	ios, _, errb = testIO("", nil)
	if code := execute(ios, []string{"bundle", "verify", path}); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if strings.ContainsRune(errb.String(), 0x1b) || !strings.Contains(errb.String(), "acme/[2Japi:2.4.1") {
		t.Fatalf("stderr %q", errb)
	}
}
