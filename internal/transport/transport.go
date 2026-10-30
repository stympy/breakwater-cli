// Package transport builds the HTTP transports the CLI uses: ggcr's
// defaults plus a response-header timeout, so a stalled server fails
// instead of hanging, and optionally extra trusted CA certificates.
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// HeaderTimeout bounds the wait for a response's headers. Bodies have no
// overall limit: layers and binaries can be large.
const HeaderTimeout = 60 * time.Second

// New returns a copy of ggcr's default transport with HeaderTimeout and,
// when roots is not nil, roots as the trusted CAs.
func New(roots *x509.CertPool) *http.Transport {
	t := remote.DefaultTransport.(*http.Transport).Clone()
	t.ResponseHeaderTimeout = HeaderTimeout
	if roots != nil {
		if t.TLSClientConfig == nil {
			t.TLSClientConfig = &tls.Config{}
		}
		t.TLSClientConfig.RootCAs = roots
	}
	return t
}

// LoadCAFile returns the system's trusted CAs plus the PEM certificates in
// path. An empty path returns nil (use the system's).
func LoadCAFile(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--ca-file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("--ca-file " + path + ": no PEM certificates in it")
	}
	return pool, nil
}
