package bundle

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

// rawEntry is one entry of a hand-built tar.
type rawEntry struct {
	hdr  tar.Header
	body []byte
}

func reg(name string, body string) rawEntry {
	return rawEntry{hdr: tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}, body: []byte(body)}
}

func sumHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// headerFor makes a bundle.json entry declaring decl (path and body) in
// order, after edit has had its way with the document.
func headerFor(t *testing.T, decl []rawEntry, edit func(*document)) rawEntry {
	t.Helper()
	doc := document{Header: Header{Format: 1, CLIVersion: "test", CreatedAt: "2026-10-30T00:00:00Z", Manifest: json.RawMessage(`{}`)}}
	for _, e := range decl {
		doc.Entries = append(doc.Entries, Entry{Path: e.hdr.Name, Size: int64(len(e.body)), SHA256: sumHex(e.body)})
	}
	if edit != nil {
		edit(&doc)
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return reg(HeaderPath, string(b))
}

func buildTar(t *testing.T, entries ...rawEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := e.hdr
		if h.Typeflag != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// sparseTar writes header, then entry as a PAX (format 0.1) GNU sparse file
// with one data block covering it all. archive/tar won't write the PAX
// header itself, so it's patched in by hand. Go's reader presents such an
// entry as an ordinary TypeReg file.
func sparseTar(t *testing.T, header, entry rawEntry) []byte {
	t.Helper()
	n := len(entry.body)
	records := ""
	for _, kv := range []string{fmt.Sprintf("GNU.sparse.size=%d", n), "GNU.sparse.numblocks=1", fmt.Sprintf("GNU.sparse.map=0,%d", n)} {
		l := len(kv) + 2 // space and newline
		l += len(fmt.Sprint(l + len(fmt.Sprint(l))))
		records += fmt.Sprintf("%d %s\n", l, kv)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	write := func(h tar.Header, body []byte) {
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	write(header.hdr, header.body)
	if err := tw.Flush(); err != nil { // pads the entry, so the next header starts here
		t.Fatal(err)
	}
	paxAt := buf.Len()
	write(tar.Header{Name: "PaxHeaders/x", Typeflag: tar.TypeReg, Size: int64(len(records)), Format: tar.FormatUSTAR}, []byte(records))
	write(entry.hdr, entry.body)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	blk := b[paxAt : paxAt+512]
	blk[156] = tar.TypeXHeader
	copy(blk[148:156], "        ")
	sum := 0
	for _, c := range blk {
		sum += int(c)
	}
	copy(blk[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return b
}

func scanBytes(b []byte) error {
	_, _, err := Scan(bytes.NewReader(b), nil)
	return err
}

func TestScanAcceptsAHandBuiltBundle(t *testing.T) {
	a, b := reg("files/a.txt", "hello"), reg("files/b.txt", "world")
	h, idx, err := Scan(bytes.NewReader(buildTar(t, headerFor(t, []rawEntry{a, b}, nil), a, b)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if h.Format != 1 || len(idx.Entries) != 2 {
		t.Fatalf("header %+v index %+v", h, idx)
	}
}

func TestScanRejectsHostileArchives(t *testing.T) {
	a := reg("files/a.txt", "hello")
	blob := reg("oci/blobs/sha256/"+sumHex([]byte("blob")), "blob")
	flipped := reg("files/a.txt", "hellp")
	big := reg("files/a.txt", "hello!")
	hostile := func(name string, typ byte) rawEntry {
		return rawEntry{hdr: tar.Header{Name: name, Typeflag: typ, Mode: 0o644, Linkname: "files/a.txt"}}
	}

	good := buildTar(t, headerFor(t, []rawEntry{a, blob}, nil), a, blob)

	overCap := func() []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		if err := tw.WriteHeader(&tar.Header{Name: HeaderPath, Typeflag: tar.TypeReg, Mode: 0o644, Size: MaxHeaderSize + 1}); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes() // header block only; the reader must refuse before reading the body
	}()

	tooMany := headerFor(t, nil, func(d *document) {
		d.Entries = make([]Entry, MaxEntries+1)
	})

	cases := []struct {
		name string
		tar  []byte
		want string
	}{
		{"empty archive", buildTar(t), "bundle is empty"},
		{"bundle.json not first", buildTar(t, a, headerFor(t, []rawEntry{a}, nil)), `bundle.json must be the first entry, found "files/a.txt"`},
		{"format 2", buildTar(t, headerFor(t, []rawEntry{a}, func(d *document) { d.Format = 2 }), a), "this bundle uses format 2; upgrade breakwater to read it"},
		{"format 0", buildTar(t, headerFor(t, []rawEntry{a}, func(d *document) { d.Format = 0 }), a), "bundle.json has no valid format"},
		{"bundle.json not JSON", buildTar(t, reg(HeaderPath, "{nope"), a), "bundle.json doesn't parse"},
		{"bundle.json over the cap", overCap, "bundle.json is 33554433 bytes, over the 32 MiB limit"},
		{"bundle.json a symlink", buildTar(t, hostile(HeaderPath, tar.TypeSymlink)), `bundle.json is a symlink`},
		{"undeclared entry", buildTar(t, headerFor(t, []rawEntry{a}, nil), a, reg("files/b.txt", "x")), `undeclared entry "files/b.txt"`},
		{"duplicate entry", buildTar(t, headerFor(t, []rawEntry{a}, nil), a, a), `duplicate entry "files/a.txt"`},
		{"symlink", buildTar(t, headerFor(t, []rawEntry{a}, nil), hostile("files/a.txt", tar.TypeSymlink)), `entry "files/a.txt" is a symlink`},
		{"hardlink", buildTar(t, headerFor(t, []rawEntry{a}, nil), hostile("files/a.txt", tar.TypeLink)), `entry "files/a.txt" is a hard link`},
		{"dir", buildTar(t, headerFor(t, []rawEntry{a}, nil), hostile("files/", tar.TypeDir), a), `entry "files/" is a directory`},
		{"fifo", buildTar(t, headerFor(t, []rawEntry{a}, nil), hostile("files/a.txt", tar.TypeFifo)), `entry "files/a.txt" is not a regular file`},
		{"../evil", buildTar(t, headerFor(t, []rawEntry{a}, nil), reg("../evil", "x"), a), `entry "../evil" has an unsafe path`},
		{"/abs", buildTar(t, headerFor(t, []rawEntry{a}, nil), reg("/abs", "x"), a), `entry "/abs" has an unsafe path`},
		{"backslash", buildTar(t, headerFor(t, []rawEntry{a}, nil), reg(`files\a.txt`, "x"), a), `has an unsafe path`},
		{"dot segment", buildTar(t, headerFor(t, []rawEntry{a}, nil), reg("files/./a.txt", "x"), a), `has an unsafe path`},
		{"declared ../evil", buildTar(t, headerFor(t, []rawEntry{reg("../evil", "x")}, nil), reg("../evil", "x")), `bundle.json declares an unsafe path "../evil"`},
		{"declared bundle.json", buildTar(t, headerFor(t, []rawEntry{reg(HeaderPath, "x")}, nil)), `bundle.json declares an unsafe path "bundle.json"`},
		{"declared twice", buildTar(t, headerFor(t, []rawEntry{a, a}, nil), a), `bundle.json declares "files/a.txt" twice`},
		{"declared bad sha", buildTar(t, headerFor(t, []rawEntry{a}, func(d *document) { d.Entries[0].SHA256 = "sha256:" + d.Entries[0].SHA256 }), a), `bundle.json declares "files/a.txt" with an invalid sha256`},
		{"declared negative size", buildTar(t, headerFor(t, []rawEntry{a}, func(d *document) { d.Entries[0].Size = -1 }), a), `bundle.json declares "files/a.txt" with an invalid size -1`},
		{"blob path not its sha", buildTar(t, headerFor(t, []rawEntry{reg("oci/blobs/sha256/"+sumHex([]byte("other")), "blob")}, nil), reg("oci/blobs/sha256/"+sumHex([]byte("other")), "blob")), "isn't named after its sha256"},
		{"too many entries", buildTar(t, tooMany), "bundle.json declares 100001 entries, over the limit of 100000"},
		{"size mismatch", buildTar(t, headerFor(t, []rawEntry{a}, nil), big), `entry "files/a.txt" is 6 bytes; bundle.json declares 5`},
		{"hash mismatch", buildTar(t, headerFor(t, []rawEntry{a}, nil), flipped), `entry "files/a.txt" doesn't match its sha256`},
		{"truncated", good[:len(good)-1024-512+2], `entry "oci/blobs/sha256/` + sumHex([]byte("blob")) + `" is truncated`},
		{"truncated header", good[:700], "bundle.json is truncated"},
		{"declared entry missing", buildTar(t, headerFor(t, []rawEntry{a, blob}, nil), a), `declared entry "oci/blobs/sha256/` + sumHex([]byte("blob")) + `" is missing from the bundle`},
		{"gnu sparse", sparseTar(t, headerFor(t, []rawEntry{a}, nil), a), `entry "files/a.txt" is a sparse file`},
	}
	seen := map[string]string{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := scanBytes(c.tar)
			if err == nil {
				t.Fatalf("accepted; want %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q; want it to contain %q", err, c.want)
			}
			if other, dup := seen[err.Error()]; dup {
				t.Fatalf("same error as case %q: %q", other, err)
			}
			seen[err.Error()] = c.name
		})
	}
	if err := scanBytes(good); err != nil {
		t.Fatalf("the untruncated archive should pass: %v", err)
	}
}

func TestScanDrainsWhatVisitLeaves(t *testing.T) {
	a, b := reg("files/a.txt", strings.Repeat("a", 3000)), reg("files/b.txt", "bee")
	var got []string
	_, _, err := Scan(bytes.NewReader(buildTar(t, headerFor(t, []rawEntry{a, b}, nil), a, b)), func(e Entry, body io.Reader) error {
		p := make([]byte, 10)
		n, _ := io.ReadFull(body, p)
		got = append(got, fmt.Sprintf("%s:%d", e.Path, n))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "files/a.txt:10,files/b.txt:3" {
		t.Fatalf("visited %v", got)
	}
}

func TestScanStillChecksTheHashWhenVisitReadsEverything(t *testing.T) {
	a := reg("files/a.txt", "hello")
	bad := reg("files/a.txt", "hellp")
	_, _, err := Scan(bytes.NewReader(buildTar(t, headerFor(t, []rawEntry{a}, nil), bad)), func(e Entry, body io.Reader) error {
		_, err := io.Copy(io.Discard, body)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "doesn't match its sha256") {
		t.Fatalf("err %v", err)
	}
}

func TestScanReportsVisitErrors(t *testing.T) {
	a := reg("files/a.txt", "hello")
	_, _, err := Scan(bytes.NewReader(buildTar(t, headerFor(t, []rawEntry{a}, nil), a)), func(Entry, io.Reader) error {
		return fmt.Errorf("disk full")
	})
	if err == nil || err.Error() != "files/a.txt: disk full" {
		t.Fatalf("err %v", err)
	}
}

// TestScanOffsetsLocateEveryEntry reads each entry back at its recorded
// offset, including after long (PAX) names, so a change in archive/tar's
// reading can't silently break Bundle.Blob.
func TestScanOffsetsLocateEveryEntry(t *testing.T) {
	long := "files/" + strings.Repeat("n", 150) // over USTAR's 100-byte name: PAX header
	entries := []rawEntry{
		reg("oci/oci-layout", `{"imageLayoutVersion":"1.0.0"}`),
		reg(long, strings.Repeat("x", 513)),
		reg("files/empty", ""),
		reg("files/exact", strings.Repeat("y", 1024)),
		reg("bin/tool", "tool bytes"),
	}
	data := buildTar(t, append([]rawEntry{headerFor(t, entries, nil)}, entries...)...)
	_, idx, err := Scan(bytes.NewReader(data), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Entries) != len(entries) {
		t.Fatalf("index %+v", idx.Entries)
	}
	for i, e := range entries {
		loc, ok := idx.Lookup(e.hdr.Name)
		if !ok || idx.Entries[i].Path != e.hdr.Name {
			t.Fatalf("%s not indexed in order", e.hdr.Name)
		}
		got, err := io.ReadAll(io.NewSectionReader(bytes.NewReader(data), loc.Offset, loc.Size))
		if err != nil {
			t.Fatal(err)
		}
		if sumHex(got) != sumHex(e.body) {
			t.Fatalf("%s at offset %d reads %q", e.hdr.Name, loc.Offset, got)
		}
	}
}

func TestValidPath(t *testing.T) {
	for _, p := range []string{"a", "files/a.txt", "oci/blobs/sha256/x"} {
		if !validPath(p) {
			t.Errorf("%q should be valid", p)
		}
	}
	for _, p := range []string{"", ".", "..", "a/..", "../a", "/a", "a/", "a//b", "a/./b", `a\b`, "a\x00b", "./a"} {
		if validPath(p) {
			t.Errorf("%q should be invalid", p)
		}
	}
}

func TestValidateChecksHeaderFields(t *testing.T) {
	cases := []struct {
		edit func(*Header)
		want string
	}{
		{func(h *Header) { h.CreatedAt = "yesterday" }, `bundle.json has an invalid created_at "yesterday"`},
		{func(h *Header) { h.CLIVersion = "" }, `bundle.json has an invalid cli_version ""`},
		{func(h *Header) { h.Platforms = []string{} }, "bundle.json lists no platforms (null means all)"},
		{func(h *Header) { h.Platforms = []string{"linux/amd64/v8/x"} }, `bundle.json lists an invalid platform "linux/amd64/v8/x"`},
	}
	for _, c := range cases {
		h := Header{Format: 1, CLIVersion: "0.1.0", CreatedAt: "2026-10-30T00:00:00Z", Manifest: json.RawMessage(`{"format":1,"images":[],"files":[]}`)}
		c.edit(&h)
		_, err := Validate(&h, &Index{byPath: map[string]int{}}, bytes.NewReader(nil))
		if err == nil || err.Error() != c.want {
			t.Errorf("err %v; want %q", err, c.want)
		}
	}
}
