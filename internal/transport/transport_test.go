package transport

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewSetsAHeaderTimeout(t *testing.T) {
	if got := New(nil).ResponseHeaderTimeout; got != HeaderTimeout {
		t.Fatalf("ResponseHeaderTimeout %v", got)
	}
}

func TestCAFileIsTrusted(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	get := func(tr http.RoundTripper) error {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
		resp, err := (&http.Client{Transport: tr}).Do(req)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	if err := get(New(nil)); err == nil {
		t.Fatal("an unknown CA was trusted")
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	pool, err := LoadCAFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := get(New(pool)); err != nil {
		t.Fatalf("with --ca-file: %v", err)
	}
}

func TestLoadCAFileErrors(t *testing.T) {
	if pool, err := LoadCAFile(""); pool != nil || err != nil {
		t.Fatalf("empty path: %v %v", pool, err)
	}
	if _, err := LoadCAFile(filepath.Join(t.TempDir(), "nope.pem")); err == nil {
		t.Fatal("missing file accepted")
	}
	path := filepath.Join(t.TempDir(), "junk.pem")
	os.WriteFile(path, []byte("junk"), 0o600)
	if _, err := LoadCAFile(path); err == nil || !strings.Contains(err.Error(), "no PEM certificates") {
		t.Fatalf("err %v", err)
	}
}
