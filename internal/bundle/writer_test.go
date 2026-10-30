package bundle_test

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stympy/breakwater-cli/internal/bundle"
)

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func header() bundle.Header {
	return bundle.Header{CLIVersion: "0.1.0", CreatedAt: "2026-10-30T12:00:00Z", Manifest: json.RawMessage(`{"format":1}`)}
}

func TestWriterWritesRegularFilesAfterBundleJSON(t *testing.T) {
	var buf bytes.Buffer
	w := bundle.NewWriter(&buf, header())
	w.Declare("files/a.txt", 5, sha("hello"))
	w.Declare("bin/b", 3, sha("bee"))
	if err := w.Begin(); err != nil {
		t.Fatal(err)
	}
	if err := w.Add("files/a.txt", strings.NewReader("hello")); err != nil {
		t.Fatal(err)
	}
	if err := w.Add("bin/b", strings.NewReader("bee")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	tr := tar.NewReader(bytes.NewReader(buf.Bytes()))
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Mode != 0o644 || hdr.Uid != 0 || hdr.Gid != 0 || !hdr.ModTime.Equal(time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)) {
			t.Fatalf("header %+v", hdr)
		}
		names = append(names, hdr.Name)
		if hdr.Name == "bundle.json" {
			var doc map[string]any
			if err := json.NewDecoder(tr).Decode(&doc); err != nil {
				t.Fatal(err)
			}
			if doc["format"] != float64(1) || doc["platforms"] != nil {
				t.Fatalf("doc %v", doc)
			}
			entries := doc["entries"].([]any)
			if len(entries) != 2 || entries[0].(map[string]any)["path"] != "files/a.txt" || entries[1].(map[string]any)["sha256"] != sha("bee") {
				t.Fatalf("entries %v", entries)
			}
		}
	}
	if strings.Join(names, ",") != "bundle.json,files/a.txt,bin/b" {
		t.Fatalf("names %v", names)
	}
	h, idx, err := bundle.Scan(bytes.NewReader(buf.Bytes()), nil)
	if err != nil || h.CLIVersion != "0.1.0" || len(idx.Entries) != 2 {
		t.Fatalf("scan %v %+v", err, h)
	}
}

func TestWriterRefusesMismatches(t *testing.T) {
	cases := []struct {
		name string
		run  func(w *bundle.Writer) error
		want string
	}{
		{"short", func(w *bundle.Writer) error { return w.Add("files/a.txt", strings.NewReader("hell")) }, `files/a.txt: got 4 bytes, declared 5`},
		{"long", func(w *bundle.Writer) error { return w.Add("files/a.txt", strings.NewReader("hello!")) }, `files/a.txt: more than the declared 5 bytes`},
		{"hash", func(w *bundle.Writer) error { return w.Add("files/a.txt", strings.NewReader("hellp")) }, `files/a.txt: sha256 ` + sha("hellp") + ` doesn't match the declared ` + sha("hello")},
		{"out of order", func(w *bundle.Writer) error { return w.Add("bin/b", strings.NewReader("bee")) }, `adding "bin/b", but "files/a.txt" is declared next`},
		{"missing at close", func(w *bundle.Writer) error {
			if err := w.Add("files/a.txt", strings.NewReader("hello")); err != nil {
				return err
			}
			return w.Close()
		}, `declared entry "bin/b" was never added`},
		{"too many", func(w *bundle.Writer) error {
			w.Add("files/a.txt", strings.NewReader("hello"))
			w.Add("bin/b", strings.NewReader("bee"))
			return w.Add("bin/c", strings.NewReader(""))
		}, `adding "bin/c", but every declared entry was added`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := bundle.NewWriter(io.Discard, header())
			w.Declare("files/a.txt", 5, sha("hello"))
			w.Declare("bin/b", 3, sha("bee"))
			if err := w.Begin(); err != nil {
				t.Fatal(err)
			}
			err := c.run(w)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v; want %q", err, c.want)
			}
			// Errors stick.
			if err2 := w.Close(); err2 == nil {
				t.Fatal("Close succeeded after an error")
			}
		})
	}
}

func TestWriterRefusesBadDeclarations(t *testing.T) {
	cases := []struct {
		path, sha string
		size      int64
		want      string
	}{
		{"../x", sha("x"), 1, `unsafe path "../x"`},
		{"bundle.json", sha("x"), 1, `unsafe path "bundle.json"`},
		{"files/a", "sha256:" + sha("x"), 1, `invalid sha256`},
		{"files/a", sha("x"), -1, `invalid size -1`},
		{"oci/blobs/sha256/" + sha("y"), sha("x"), 1, `isn't named after its sha256`},
	}
	for _, c := range cases {
		w := bundle.NewWriter(io.Discard, header())
		w.Declare(c.path, c.size, c.sha)
		if err := w.Begin(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v; want %q", c.path, err, c.want)
		}
	}
	w := bundle.NewWriter(io.Discard, header())
	w.Declare("files/a", 1, sha("x"))
	w.Declare("files/a", 1, sha("x"))
	if err := w.Begin(); err == nil || !strings.Contains(err.Error(), `declares "files/a" twice`) {
		t.Errorf("err %v", err)
	}
	h := header()
	h.Format = 2
	if err := bundle.NewWriter(io.Discard, h).Begin(); err == nil || !strings.Contains(err.Error(), "format 1, not 2") {
		t.Errorf("err %v", err)
	}
	h = header()
	h.Platforms = []string{}
	if err := bundle.NewWriter(io.Discard, h).Begin(); err == nil || !strings.Contains(err.Error(), "use nil for all platforms") {
		t.Errorf("err %v", err)
	}
	h = header()
	h.CreatedAt = "yesterday"
	if err := bundle.NewWriter(io.Discard, h).Begin(); err == nil || !strings.Contains(err.Error(), "created_at") {
		t.Errorf("err %v", err)
	}
}
