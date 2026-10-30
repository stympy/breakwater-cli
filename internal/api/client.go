// Package api is the client for Breakwater's customer API.
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/stympy/breakwater-cli/internal/credentials"
	"github.com/stympy/breakwater-cli/internal/version"
)

// SupportedManifestFormat is the newest manifest format this client reads.
const SupportedManifestFormat = 1

var (
	digestPattern   = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	fileNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	sha256Pattern   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	repoPathPattern = regexp.MustCompile(`^[a-z0-9._-]+(/[a-z0-9._-]+)*$`)
)

// ValidFileName reports whether name is an allowed release file name: one
// path segment of letters, digits, '.', '_' and '-', not "." or "..".
func ValidFileName(name string) bool {
	return fileNamePattern.MatchString(name) && name != "." && name != ".."
}

// validRepositoryPath reports whether p is lowercase slash-separated
// segments of [a-z0-9._-], none of them "." or "..".
func validRepositoryPath(p string) bool {
	if !repoPathPattern.MatchString(p) {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// Error is a failed API call.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return e.Message }

// Client calls the customer API with Basic auth. It never follows redirects.
type Client struct {
	origin *url.URL
	creds  credentials.Credentials
	http   *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient replaces the HTTP client (tests). Redirects stay refused.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) {
		cp := *h
		cp.CheckRedirect = noRedirect
		c.http = &cp
	}
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// New returns a client for the API at origin.
func New(origin *url.URL, creds credentials.Credentials, opts ...Option) *Client {
	c := &Client{
		origin: &url.URL{Scheme: origin.Scheme, Host: origin.Host},
		creds:  creds,
		http:   &http.Client{CheckRedirect: noRedirect},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

func (c *Client) newRequest(ctx context.Context, method, escapedPath, query string, body any) (*http.Request, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	u := c.origin.String() + escapedPath
	if query != "" {
		u += "?" + query
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.creds.Username, c.creds.Password)
	req.Header.Set("User-Agent", version.UserAgent())
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// checkStatus turns a non-2xx response into an *Error. It reads a bounded
// snippet of the body and does not close it.
func checkStatus(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var parsed struct {
		Error   string   `json:"error"`
		Details []string `json:"details"`
	}
	_ = json.Unmarshal(raw, &parsed)
	msg := parsed.Error
	if len(parsed.Details) > 0 {
		msg += ": " + strings.Join(parsed.Details, "; ")
	}
	e := &Error{Status: resp.StatusCode}
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		e.Message = fmt.Sprintf("Breakwater API redirected to %s; refusing to follow with credentials", resp.Header.Get("Location"))
	case resp.StatusCode == http.StatusUnauthorized:
		e.Message = "the API refused the credentials (use a customer pull token)"
	case resp.StatusCode == http.StatusForbidden && parsed.Error == "plan_required":
		e.Message = "air-gapped bundles aren't included in this vendor's Breakwater plan"
	case resp.StatusCode == http.StatusTooManyRequests:
		if secs, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && secs >= 0 {
			e.Message = fmt.Sprintf("rate limited by Breakwater; try again in %ds", secs)
		} else {
			e.Message = "rate limited by Breakwater; try again later"
		}
	default:
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
			if len(msg) > 200 {
				msg = msg[:200]
			}
		}
		e.Message = fmt.Sprintf("Breakwater API returned %d: %s", resp.StatusCode, msg)
	}
	return e
}

// doJSON sends the request with the 60s JSON timeout and decodes a JSON
// response into out (if non-nil). notFound overrides the 404 message.
func (c *Client) doJSON(ctx context.Context, method, escapedPath, query string, body, out any, notFound string) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, err := c.newRequest(ctx, method, escapedPath, query, body)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp); err != nil {
		var ae *Error
		if notFound != "" && errors.As(err, &ae) && ae.Status == http.StatusNotFound {
			ae.Message = notFound
		}
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return nil, fmt.Errorf("Breakwater API returned invalid JSON: %w", err)
		}
	}
	return raw, nil
}

// Releases lists the releases this token can see, optionally for one product.
func (c *Client) Releases(ctx context.Context, product string) ([]Release, error) {
	releases, _, err := c.ReleasesRaw(ctx, product)
	return releases, err
}

// ReleasesRaw is Releases that also returns the server's "data" array as
// sent, so callers can pass fields this client doesn't know through.
func (c *Client) ReleasesRaw(ctx context.Context, product string) ([]Release, json.RawMessage, error) {
	query := ""
	if product != "" {
		query = url.Values{"product": {product}}.Encode()
	}
	var out struct {
		Data json.RawMessage `json:"data"`
	}
	if _, err := c.doJSON(ctx, http.MethodGet, "/api/v1/customer/releases", query, nil, &out, ""); err != nil {
		return nil, nil, err
	}
	var releases []Release
	if err := json.Unmarshal(out.Data, &releases); err != nil {
		return nil, nil, fmt.Errorf("Breakwater API returned an invalid release list: %w", err)
	}
	return releases, out.Data, nil
}

func releasePath(product, version string) string {
	return "/api/v1/customer/products/" + url.PathEscape(product) + "/releases/" + url.PathEscape(version)
}

// Manifest fetches a release manifest and returns it parsed and as fetched.
func (c *Client) Manifest(ctx context.Context, product, version string) (*Manifest, json.RawMessage, error) {
	var m Manifest
	notFound := fmt.Sprintf("no release %s of %s that this token can see", version, product)
	raw, err := c.doJSON(ctx, http.MethodGet, releasePath(product, version), "", nil, &m, notFound)
	if err != nil {
		return nil, nil, err
	}
	if m.Product.Slug != product {
		return nil, nil, fmt.Errorf("the manifest is for product %q, not %q", m.Product.Slug, product)
	}
	if m.Version != version {
		return nil, nil, fmt.Errorf("the manifest is for version %q, not %q", m.Version, version)
	}
	if err := ValidateManifest(&m); err != nil {
		return nil, nil, err
	}
	return &m, raw, nil
}

// ValidateManifest checks a manifest the way the client does when it fetches
// one: format, kinds, digests, references and file names.
func ValidateManifest(m *Manifest) error {
	if m.Format > SupportedManifestFormat {
		return fmt.Errorf("this release uses manifest format %d; upgrade breakwater", m.Format)
	}
	if m.Format < 1 {
		return errors.New("the release manifest has no valid format")
	}
	if m.Incomplete {
		return fmt.Errorf("this release is incomplete: %s", strings.Join(m.IncompleteReasons, "; "))
	}
	for i, img := range m.Images {
		if img.Kind != "internal" && img.Kind != "external" {
			return fmt.Errorf("manifest image %d has unknown kind %q", i+1, img.Kind)
		}
		if !digestPattern.MatchString(img.Digest) {
			return fmt.Errorf("manifest image %q has an invalid digest %q", img.Reference, img.Digest)
		}
		if img.Reference == "" || strings.Contains(img.Reference, "@") {
			return fmt.Errorf("manifest image %d has an invalid reference %q (it must not contain a digest)", i+1, img.Reference)
		}
		if img.Kind == "internal" && (img.RepositoryPath == "" || img.Tag == "") {
			return fmt.Errorf("manifest image %q is internal but has no repository_path or tag", img.Reference)
		}
		if img.RepositoryPath != "" && !validRepositoryPath(img.RepositoryPath) {
			return fmt.Errorf("manifest image %q has an invalid repository_path %q", img.Reference, img.RepositoryPath)
		}
	}
	seen := map[string]bool{}
	for _, f := range m.Files {
		if !ValidFileName(f.Name) {
			return fmt.Errorf("manifest file name %q isn't allowed", f.Name)
		}
		if seen[f.Name] {
			return fmt.Errorf("manifest lists file %s twice", f.Name)
		}
		seen[f.Name] = true
		if !sha256Pattern.MatchString(f.SHA256) {
			return fmt.Errorf("manifest file %s has an invalid sha256 %q", f.Name, f.SHA256)
		}
		if f.Size < 0 {
			return fmt.Errorf("manifest file %s has an invalid size %d", f.Name, f.Size)
		}
	}
	return nil
}

// effectiveOrigin is scheme, lowercased hostname and effective port.
func effectiveOrigin(u *url.URL) (scheme, host, port string) {
	scheme = strings.ToLower(u.Scheme)
	port = u.Port()
	if port == "" {
		switch scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return scheme, strings.ToLower(u.Hostname()), port
}

func originString(u *url.URL) string {
	s, h, p := effectiveOrigin(u)
	return s + "://" + h + ":" + p
}

// DownloadFile streams a release file to w, verifying its size and SHA-256.
// On any error w may hold unverified bytes; callers must discard them.
// The URL must be on the API origin, since credentials go with the request.
func (c *Client) DownloadFile(ctx context.Context, f ManifestFile, w io.Writer) error {
	if !ValidFileName(f.Name) {
		return fmt.Errorf("file name %q isn't allowed", f.Name)
	}
	if !sha256Pattern.MatchString(f.SHA256) {
		return fmt.Errorf("file %s has an invalid sha256 %q", f.Name, f.SHA256)
	}
	if f.Size < 0 {
		return fmt.Errorf("file %s has an invalid size %d", f.Name, f.Size)
	}
	fu, err := url.Parse(f.URL)
	if err != nil {
		return fmt.Errorf("file %s has an invalid URL: %w", f.Name, err)
	}
	if fu.User != nil {
		return fmt.Errorf("file %s has a URL with embedded credentials; refusing it", f.Name)
	}
	s1, h1, p1 := effectiveOrigin(fu)
	s2, h2, p2 := effectiveOrigin(c.origin)
	if fu.Host == "" || s1 != s2 || h1 != h2 || p1 != p2 {
		return fmt.Errorf("file %s is served from %s, not %s; refusing to send credentials there", f.Name, originString(fu), originString(c.origin))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.creds.Username, c.creds.Password)
	req.Header.Set("User-Agent", version.UserAgent())
	resp, err := c.http.Do(req) // no timeout: the context bounds it
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp); err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(resp.Body, f.Size+1))
	if err != nil {
		return fmt.Errorf("downloading %s: %w", f.Name, err)
	}
	if n != f.Size {
		return fmt.Errorf("file %s is %d bytes (or more), expected %d", f.Name, n, f.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != f.SHA256 {
		return fmt.Errorf("file %s has sha256 %s, expected %s", f.Name, got, f.SHA256)
	}
	return nil
}

// StartBundle records that a bundle is being made and returns its id.
func (c *Client) StartBundle(ctx context.Context, product, version string, platforms []string) (string, error) {
	body := map[string]any{"platforms": platforms, "cli_version": cliVersion()}
	var out struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	notFound := fmt.Sprintf("no release %s of %s that this token can see", version, product)
	if _, err := c.doJSON(ctx, http.MethodPost, releasePath(product, version)+"/bundles", "", body, &out, notFound); err != nil {
		return "", err
	}
	if out.Data.ID == "" {
		return "", errors.New("Breakwater API returned no bundle id")
	}
	return out.Data.ID, nil
}

// CompleteBundle marks a started bundle completed.
func (c *Client) CompleteBundle(ctx context.Context, id string, totalBytes int64) error {
	body := map[string]any{"status": "completed", "total_bytes": totalBytes}
	_, err := c.doJSON(ctx, http.MethodPatch, "/api/v1/customer/bundles/"+url.PathEscape(id), "", body, nil, "")
	return err
}

func cliVersion() string { return version.Version }
