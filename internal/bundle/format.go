// Package bundle is the offline bundle format: one uncompressed tar whose
// first entry, bundle.json, declares every other entry's path, size and
// SHA-256, so a reader can bound and check everything while streaming.
//
// Bundles are read on the offline side, where they may be hostile: the
// reader accepts only regular files at clean, declared paths, bounds every
// allocation, and checks every byte against its declared digest.
package bundle

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Format is the bundle format this package writes and the newest it reads.
const Format = 1

const (
	// HeaderPath is the first entry of every bundle.
	HeaderPath = "bundle.json"
	// LayoutPath and IndexPath are the OCI image layout's files; blobs are
	// under BlobDir. The layout root is "oci/".
	LayoutPath = "oci/oci-layout"
	IndexPath  = "oci/index.json"
	BlobDir    = "oci/blobs/sha256/"
	FileDir    = "files/"
	BinDir     = "bin/"

	// LayoutJSON is the content of oci/oci-layout.
	LayoutJSON = `{"imageLayoutVersion":"1.0.0"}`

	// MaxHeaderSize caps bundle.json.
	MaxHeaderSize = 32 << 20
	// MaxEntries caps the number of declared entries.
	MaxEntries = 100000
	// MaxManifestSize caps a manifest or index blob, and oci/index.json,
	// read into memory.
	MaxManifestSize = 4 << 20
)

// Header is bundle.json without its entries list.
type Header struct {
	Format     int             `json:"format"`
	CLIVersion string          `json:"cli_version"`
	CreatedAt  string          `json:"created_at"` // RFC 3339
	Manifest   json.RawMessage `json:"manifest"`   // the release manifest, as the API returned it
	Platforms  []string        `json:"platforms"`  // nil means all
	Images     []Image         `json:"images"`
	Files      []File          `json:"files"`
	Bin        []Bin           `json:"bin"`
}

// Image is one release image in the bundle. Children lists the digests of
// an index's child manifests that the bundle keeps; it's omitted for a
// manifest.
type Image struct {
	Kind           string   `json:"kind"`
	Reference      string   `json:"reference"`
	Tag            string   `json:"tag"`
	RepositoryPath string   `json:"repository_path"`
	Digest         string   `json:"digest"`
	MediaType      string   `json:"media_type"`
	Children       []string `json:"children,omitempty"`
}

// File is a release file, stored at files/<name>.
type File struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Bin is a breakwater binary carried in the bundle, stored at bin/<name>.
type Bin struct {
	Name     string `json:"name"`
	Platform string `json:"platform"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
}

// Entry is a declared tar entry after bundle.json. SHA256 is plain lowercase
// hex, without a "sha256:" prefix.
type Entry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// document is bundle.json as written.
type document struct {
	Header
	Entries []Entry `json:"entries"`
}

var (
	hexPattern    = regexp.MustCompile(`^[a-f0-9]{64}$`)
	digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

// BlobPath is the entry path of a "sha256:<hex>" digest.
func BlobPath(digest string) (string, error) {
	if !digestPattern.MatchString(digest) {
		return "", fmt.Errorf("invalid digest %q", digest)
	}
	return BlobDir + strings.TrimPrefix(digest, "sha256:"), nil
}

// FilePath and BinPath are the entry paths of a file and a binary.
func FilePath(name string) string { return FileDir + name }
func BinPath(name string) string  { return BinDir + name }

// validPath reports whether p is a clean, relative, slash-separated path with
// no "." or ".." segments, backslashes or NULs.
func validPath(p string) bool {
	if p == "" || strings.ContainsAny(p, "\\\x00") || strings.HasPrefix(p, "/") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// validName reports whether a file or binary name is one safe path segment.
func validName(n string) bool {
	return validPath(n) && !strings.Contains(n, "/")
}

// checkEntry checks one declared entry, as both the writer and the reader do.
func checkEntry(e Entry) error {
	if !validPath(e.Path) || e.Path == HeaderPath {
		return fmt.Errorf("bundle.json declares an unsafe path %q", e.Path)
	}
	if !hexPattern.MatchString(e.SHA256) {
		return fmt.Errorf("bundle.json declares %q with an invalid sha256 %q", e.Path, e.SHA256)
	}
	if e.Size < 0 {
		return fmt.Errorf("bundle.json declares %q with an invalid size %d", e.Path, e.Size)
	}
	if strings.HasPrefix(e.Path, "oci/blobs/") && e.Path != BlobDir+e.SHA256 {
		return fmt.Errorf("bundle.json declares blob %q, which isn't named after its sha256 %s", e.Path, e.SHA256)
	}
	return nil
}

// checkEntries checks the declared entries list.
func checkEntries(entries []Entry) error {
	if len(entries) > MaxEntries {
		return fmt.Errorf("bundle.json declares %d entries, over the limit of %d", len(entries), MaxEntries)
	}
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		if err := checkEntry(e); err != nil {
			return err
		}
		if seen[e.Path] {
			return fmt.Errorf("bundle.json declares %q twice", e.Path)
		}
		seen[e.Path] = true
	}
	return nil
}
