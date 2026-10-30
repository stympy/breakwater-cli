package bundle

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Writer writes a bundle. Declare every entry, call Begin to write
// bundle.json, Add each declared entry in order, then Close. After any error
// the archive is garbage: the caller deletes it.
type Writer struct {
	tw      *tar.Writer
	header  Header
	entries []Entry
	mtime   time.Time
	began   bool
	next    int
	err     error
}

// NewWriter returns a Writer that writes the bundle described by header to w.
// A zero header.Format means Format.
func NewWriter(w io.Writer, header Header) *Writer {
	if header.Format == 0 {
		header.Format = Format
	}
	return &Writer{tw: tar.NewWriter(w), header: header}
}

// Declare adds an entry to bundle.json. sha256 is plain hex. Problems are
// reported by Begin.
func (w *Writer) Declare(path string, size int64, sha256 string) {
	if w.began && w.err == nil {
		w.err = fmt.Errorf("declaring %q after Begin", path)
	}
	w.entries = append(w.entries, Entry{Path: path, Size: size, SHA256: sha256})
}

// Begin checks the declarations and writes bundle.json.
func (w *Writer) Begin() error {
	if w.err != nil {
		return w.err
	}
	if w.began {
		return w.fail(errors.New("Begin called twice"))
	}
	w.began = true
	mtime, err := time.Parse(time.RFC3339, w.header.CreatedAt)
	if err != nil {
		return w.fail(fmt.Errorf("invalid created_at %q: %w", w.header.CreatedAt, err))
	}
	w.mtime = mtime
	if err := checkEntries(w.entries); err != nil {
		return w.fail(err)
	}
	doc := document{Header: w.header, Entries: w.entries}
	if doc.Images == nil {
		doc.Images = []Image{}
	}
	if doc.Files == nil {
		doc.Files = []File{}
	}
	if doc.Bin == nil {
		doc.Bin = []Bin{}
	}
	if doc.Entries == nil {
		doc.Entries = []Entry{}
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return w.fail(fmt.Errorf("encoding bundle.json: %w", err))
	}
	if len(body) > MaxHeaderSize {
		return w.fail(fmt.Errorf("bundle.json would be %d bytes, over the 32 MiB limit", len(body)))
	}
	if err := w.writeHeader(HeaderPath, int64(len(body))); err != nil {
		return err
	}
	if _, err := w.tw.Write(body); err != nil {
		return w.fail(fmt.Errorf("writing bundle.json: %w", err))
	}
	return nil
}

// Add streams the next declared entry from r, checking its size and SHA-256.
func (w *Writer) Add(path string, r io.Reader) error {
	if w.err != nil {
		return w.err
	}
	if !w.began {
		return w.fail(fmt.Errorf("adding %q before Begin", path))
	}
	if w.next >= len(w.entries) {
		return w.fail(fmt.Errorf("adding %q, but every declared entry was added", path))
	}
	e := w.entries[w.next]
	if e.Path != path {
		return w.fail(fmt.Errorf("adding %q, but %q is declared next", path, e.Path))
	}
	if err := w.writeHeader(path, e.Size); err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w.tw, h), io.LimitReader(r, e.Size))
	if err != nil {
		return w.fail(fmt.Errorf("%s: %w", path, err))
	}
	if n != e.Size {
		return w.fail(fmt.Errorf("%s: got %d bytes, declared %d", path, n, e.Size))
	}
	var one [1]byte
	if m, _ := io.ReadFull(r, one[:]); m > 0 {
		return w.fail(fmt.Errorf("%s: more than the declared %d bytes", path, e.Size))
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != e.SHA256 {
		return w.fail(fmt.Errorf("%s: sha256 %s doesn't match the declared %s", path, got, e.SHA256))
	}
	w.next++
	return nil
}

// Close finishes the archive. It doesn't close the underlying writer.
func (w *Writer) Close() error {
	if w.err != nil {
		return w.err
	}
	if !w.began {
		return w.fail(errors.New("Close before Begin"))
	}
	if w.next < len(w.entries) {
		return w.fail(fmt.Errorf("declared entry %q was never added", w.entries[w.next].Path))
	}
	if err := w.tw.Close(); err != nil {
		return w.fail(fmt.Errorf("finishing the bundle: %w", err))
	}
	w.err = errors.New("bundle writer is closed")
	return nil
}

func (w *Writer) writeHeader(name string, size int64) error {
	hdr := &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Size:     size,
		Mode:     0o644,
		ModTime:  w.mtime,
		// Format unset: archive/tar uses USTAR when it fits, else PAX
		// (long names, sizes of 8 GiB or more).
	}
	if err := w.tw.WriteHeader(hdr); err != nil {
		return w.fail(fmt.Errorf("writing the header of %s: %w", name, err))
	}
	return nil
}

func (w *Writer) fail(err error) error {
	if w.err == nil {
		w.err = err
	}
	return err
}
