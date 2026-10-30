package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"

	"github.com/stympy/breakwater-cli/internal/api"
)

// Location is where an entry's data sits in the tar.
type Location struct {
	Offset int64
	Size   int64
}

// IndexEntry is a declared entry and the offset of its data in the tar.
type IndexEntry struct {
	Entry
	Offset int64
}

// Location is where the entry's data is.
func (e IndexEntry) Location() Location { return Location{Offset: e.Offset, Size: e.Size} }

// Index lists a scanned bundle's entries, in declared order, with their
// data offsets.
type Index struct {
	Entries []IndexEntry
	byPath  map[string]int
}

// Lookup returns the location of path's data.
func (x *Index) Lookup(path string) (Location, bool) {
	i, ok := x.byPath[path]
	if !ok {
		return Location{}, false
	}
	return x.Entries[i].Location(), true
}

func (x *Index) entry(path string) (IndexEntry, bool) {
	i, ok := x.byPath[path]
	if !ok {
		return IndexEntry{}, false
	}
	return x.Entries[i], true
}

// countingReader counts the bytes read through it. It deliberately has no
// Seek method, so archive/tar reads (and counts) everything instead of
// seeking past it.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// hashingReader hashes what's read through it.
type hashingReader struct {
	r io.Reader
	h hash.Hash
}

func (h *hashingReader) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	h.h.Write(p[:n])
	return n, err
}

func typeName(flag byte) string {
	switch flag {
	case tar.TypeSymlink:
		return "a symlink"
	case tar.TypeLink:
		return "a hard link"
	case tar.TypeDir:
		return "a directory"
	default:
		return "not a regular file"
	}
}

func isSparse(hdr *tar.Header) bool {
	for k := range hdr.PAXRecords {
		if strings.HasPrefix(k, "GNU.sparse.") {
			return true
		}
	}
	return hdr.Typeflag == tar.TypeGNUSparse
}

// Scan reads a bundle once, front to back, and checks it: bundle.json comes
// first and within its cap, the format is one this package reads, and every
// later entry is a regular file at a clean declared path, present once, of
// the declared size and SHA-256. Every declared entry must be present.
//
// visit, if not nil, is called with each entry's body as it streams past;
// Scan drains whatever visit doesn't read. The body hasn't been checked
// against its digest when visit sees it: nothing visit does with the bytes
// may be trusted or made visible until Scan returns without an error.
func Scan(r io.Reader, visit func(e Entry, body io.Reader) error) (*Header, *Index, error) {
	cr := &countingReader{r: r}
	tr := tar.NewReader(cr)

	hdr, err := tr.Next()
	if err == io.EOF {
		return nil, nil, errors.New("bundle is empty: it has no bundle.json")
	}
	if err != nil {
		return nil, nil, fmt.Errorf("reading the bundle's first entry: %w", err)
	}
	if hdr.Name != HeaderPath {
		return nil, nil, fmt.Errorf("bundle.json must be the first entry, found %q", hdr.Name)
	}
	if hdr.Typeflag != tar.TypeReg || isSparse(hdr) {
		what := typeName(hdr.Typeflag)
		if hdr.Typeflag == tar.TypeReg {
			what = "a sparse file"
		}
		return nil, nil, fmt.Errorf("bundle.json is %s; bundles hold only regular files", what)
	}
	if hdr.Size > MaxHeaderSize {
		return nil, nil, fmt.Errorf("bundle.json is %d bytes, over the 32 MiB limit", hdr.Size)
	}
	raw, err := io.ReadAll(tr)
	if err != nil {
		return nil, nil, fmt.Errorf("bundle.json is truncated: %w", err)
	}

	var probe struct {
		Format int `json:"format"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, nil, fmt.Errorf("bundle.json doesn't parse: %w", err)
	}
	if probe.Format > Format {
		return nil, nil, fmt.Errorf("this bundle uses format %d; upgrade breakwater to read it", probe.Format)
	}
	if probe.Format < 1 {
		return nil, nil, errors.New("bundle.json has no valid format")
	}
	var doc document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, fmt.Errorf("bundle.json doesn't parse: %w", err)
	}
	if err := checkEntries(doc.Entries); err != nil {
		return nil, nil, err
	}

	idx := &Index{Entries: make([]IndexEntry, len(doc.Entries)), byPath: make(map[string]int, len(doc.Entries))}
	for i, e := range doc.Entries {
		idx.Entries[i] = IndexEntry{Entry: e, Offset: -1}
		idx.byPath[e.Path] = i
	}

	last := HeaderPath
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("reading the entry after %q: %w", last, err)
		}
		offset := cr.n
		name := hdr.Name
		if hdr.Typeflag != tar.TypeReg {
			return nil, nil, fmt.Errorf("entry %q is %s; bundles hold only regular files", name, typeName(hdr.Typeflag))
		}
		if !validPath(name) {
			return nil, nil, fmt.Errorf("entry %q has an unsafe path", name)
		}
		if isSparse(hdr) {
			return nil, nil, fmt.Errorf("entry %q is a sparse file; bundles hold only regular files", name)
		}
		i, ok := idx.byPath[name]
		if !ok {
			return nil, nil, fmt.Errorf("undeclared entry %q", name)
		}
		ie := &idx.Entries[i]
		if ie.Offset >= 0 {
			return nil, nil, fmt.Errorf("duplicate entry %q", name)
		}
		if hdr.Size != ie.Size {
			return nil, nil, fmt.Errorf("entry %q is %d bytes; bundle.json declares %d", name, hdr.Size, ie.Size)
		}
		ie.Offset = offset
		last = name

		body := &hashingReader{r: tr, h: sha256.New()}
		if visit != nil {
			if err := visit(ie.Entry, body); err != nil {
				if errors.Is(err, io.ErrUnexpectedEOF) {
					return nil, nil, fmt.Errorf("entry %q is truncated: %w", name, err)
				}
				return nil, nil, fmt.Errorf("%s: %w", name, err)
			}
		}
		if _, err := io.Copy(io.Discard, body); err != nil {
			return nil, nil, fmt.Errorf("entry %q is truncated: %w", name, err)
		}
		if got := hex.EncodeToString(body.h.Sum(nil)); got != ie.SHA256 {
			return nil, nil, fmt.Errorf("entry %q doesn't match its sha256 (got %s, bundle.json declares %s)", name, got, ie.SHA256)
		}
	}
	for _, e := range idx.Entries {
		if e.Offset < 0 {
			return nil, nil, fmt.Errorf("declared entry %q is missing from the bundle", e.Path)
		}
	}
	h := doc.Header
	return &h, idx, nil
}

// Bundle is an opened, scanned and validated bundle file.
type Bundle struct {
	f       *os.File
	header  *Header
	index   *Index
	summary *Summary
}

// Open opens a bundle file, scans it and validates its structure.
func Open(path string) (*Bundle, error) {
	// Stat first: opening a FIFO would block.
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s isn't a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	b, err := open(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return b, nil
}

func open(f *os.File) (*Bundle, error) {
	h, idx, err := Scan(f, nil)
	if err != nil {
		return nil, err
	}
	sum, err := Validate(h, idx, f)
	if err != nil {
		return nil, err
	}
	return &Bundle{f: f, header: h, index: idx, summary: sum}, nil
}

// Header returns bundle.json without its entries.
func (b *Bundle) Header() *Header { return b.header }

// Index returns the bundle's entries and their offsets.
func (b *Bundle) Index() *Index { return b.index }

// Manifest returns the parsed release manifest from bundle.json.
func (b *Bundle) Manifest() *api.Manifest { return b.summary.Manifest }

// Images summarizes the bundle's images, in bundle.json order.
func (b *Bundle) Images() []ImageInfo { return b.summary.Images }

// Blob returns a blob by "sha256:<hex>" digest. The reader re-checks the
// digest and returns an error instead of io.EOF on a mismatch.
func (b *Bundle) Blob(digest string) (io.ReadCloser, error) {
	path, err := BlobPath(digest)
	if err != nil {
		return nil, err
	}
	e, ok := b.index.entry(path)
	if !ok {
		return nil, fmt.Errorf("the bundle has no blob %s", digest)
	}
	return newVerifyingReader(b.f, e), nil
}

// File returns a release file by name.
func (b *Bundle) File(name string) (io.ReadCloser, error) {
	for _, f := range b.header.Files {
		if f.Name == name {
			if e, ok := b.index.entry(FilePath(name)); ok {
				return newVerifyingReader(b.f, e), nil
			}
		}
	}
	return nil, fmt.Errorf("the bundle has no file %q", name)
}

// Bin returns a binary by name.
func (b *Bundle) Bin(name string) (io.ReadCloser, error) {
	for _, x := range b.header.Bin {
		if x.Name == name {
			if e, ok := b.index.entry(BinPath(name)); ok {
				return newVerifyingReader(b.f, e), nil
			}
		}
	}
	return nil, fmt.Errorf("the bundle has no binary %q", name)
}

// Close closes the bundle file. Readers returned earlier stop working.
func (b *Bundle) Close() error { return b.f.Close() }

// verifyingReader reads an entry at its offset and checks its SHA-256 when
// it reaches the end.
type verifyingReader struct {
	r    io.Reader
	h    hash.Hash
	e    IndexEntry
	done bool
}

func newVerifyingReader(ra io.ReaderAt, e IndexEntry) *verifyingReader {
	return &verifyingReader{r: io.NewSectionReader(ra, e.Offset, e.Size), h: sha256.New(), e: e}
}

func (v *verifyingReader) Read(p []byte) (int, error) {
	n, err := v.r.Read(p)
	v.h.Write(p[:n])
	if err == io.EOF && !v.done {
		v.done = true
		if got := hex.EncodeToString(v.h.Sum(nil)); got != v.e.SHA256 {
			return n, fmt.Errorf("entry %q doesn't match its digest on a second read (got sha256 %s); the file changed after it was verified", v.e.Path, got)
		}
	}
	return n, err
}

func (v *verifyingReader) Close() error { return nil }

// readSmall reads a whole entry of at most max bytes, re-checking its digest.
func readSmall(ra io.ReaderAt, e IndexEntry, max int64) ([]byte, error) {
	if e.Size > max {
		return nil, fmt.Errorf("entry %q is %d bytes, over the %d MiB limit for it", e.Path, e.Size, max>>20)
	}
	var buf bytes.Buffer
	buf.Grow(int(e.Size))
	if _, err := io.Copy(&buf, newVerifyingReader(ra, e)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
