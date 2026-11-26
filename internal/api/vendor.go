package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/stympy/breakwater-cli/internal/term"
	"github.com/stympy/breakwater-cli/internal/version"
)

// VendorClient calls the vendor API with a `vapi_` API token (Bearer auth).
// It never follows redirects, so the token only goes to the API origin.
type VendorClient struct {
	origin *url.URL
	token  string
	http   *http.Client
}

// NewVendor returns a vendor API client for origin.
func NewVendor(origin *url.URL, token string, opts ...Option) *VendorClient {
	c := &Client{http: &http.Client{CheckRedirect: noRedirect}}
	for _, o := range opts {
		o(c)
	}
	return &VendorClient{origin: &url.URL{Scheme: origin.Scheme, Host: origin.Host}, token: token, http: c.http}
}

// ProblemError is a failed vendor API call, from its problem details body.
type ProblemError struct {
	Status        int
	Code          string
	Title         string
	Detail        string
	RequiredScope string
	Errors        []ProblemField
}

// ProblemField is one validation problem.
type ProblemField struct {
	Field  string `json:"field"`
	Detail string `json:"detail"`
}

func (e *ProblemError) Error() string {
	title := term.Clean(e.Title)
	if title == "" {
		title = "Breakwater API returned " + strconv.Itoa(e.Status)
	}
	msg := title
	if d := term.Clean(e.Detail); d != "" {
		msg += ": " + d
	}
	if e.Code == "insufficient_scope" && e.RequiredScope != "" && !strings.Contains(msg, e.RequiredScope) {
		msg += " (needs the " + term.Clean(e.RequiredScope) + " scope)"
	}
	return msg
}

func (c *VendorClient) do(ctx context.Context, method, escapedPath, query string, body, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	u := c.origin.String() + escapedPath
	if query != "" {
		u += "?" + query
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("User-Agent", version.UserAgent())
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return vendorError(resp)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("Breakwater API returned invalid JSON: %w", err)
	}
	return nil
}

func vendorError(resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return fmt.Errorf("Breakwater API redirected to %s; refusing to follow with an API token", term.Clean(resp.Header.Get("Location")))
	}
	var p struct {
		Code          string         `json:"code"`
		Title         string         `json:"title"`
		Detail        string         `json:"detail"`
		RequiredScope string         `json:"required_scope"`
		Errors        []ProblemField `json:"errors"`
	}
	e := &ProblemError{Status: resp.StatusCode}
	if json.Unmarshal(raw, &p) == nil && (p.Title != "" || p.Detail != "") {
		e.Code, e.Title, e.Detail, e.RequiredScope, e.Errors = p.Code, p.Title, p.Detail, p.RequiredScope, p.Errors
		return e
	}
	snippet := strings.TrimSpace(string(raw))
	if len(snippet) > 200 {
		snippet = snippet[:200]
	}
	e.Detail = snippet
	if resp.StatusCode == http.StatusTooManyRequests {
		e.Title = "Rate limit exceeded"
		if s := strings.TrimSpace(resp.Header.Get("Retry-After")); s != "" {
			e.Detail = "try again in " + s + "s"
		}
	}
	return e
}

// Repository is a vendor repository.
type Repository struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	FullPath string `json:"full_path"`
}

// Repositories lists every repository of the vendor, following pagination.
func (c *VendorClient) Repositories(ctx context.Context) ([]Repository, error) {
	var all []Repository
	for page := 1; ; page++ {
		var out struct {
			Data []Repository `json:"data"`
			Meta struct {
				TotalPages int `json:"total_pages"`
			} `json:"meta"`
		}
		q := url.Values{"page": {strconv.Itoa(page)}, "per_page": {"100"}}.Encode()
		if err := c.do(ctx, http.MethodGet, "/api/v1/vendor/repositories", q, nil, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Data...)
		if page >= out.Meta.TotalPages || len(out.Data) == 0 {
			return all, nil
		}
	}
}

// ReleaseImage is an image of a release to create: a repository's tag, or
// an external reference.
type ReleaseImage struct {
	RepositoryID string `json:"repository_id,omitempty"`
	Tag          string `json:"tag,omitempty"`
	External     string `json:"external,omitempty"`
}

// ReleaseFile is a file of a release to create.
type ReleaseFile struct {
	Name          string `json:"name"`
	ContentBase64 string `json:"content_base64"`
}

// NewRelease is the body of a release create.
type NewRelease struct {
	Version string         `json:"version"`
	Notes   string         `json:"notes,omitempty"`
	Images  []ReleaseImage `json:"images,omitempty"`
	Files   []ReleaseFile  `json:"files,omitempty"`
}

// CreatedRelease is a release as the vendor API returns it.
type CreatedRelease struct {
	ID          string          `json:"id"`
	ProductID   string          `json:"product_id"`
	Version     string          `json:"version"`
	Status      string          `json:"status"`
	PublishedAt string          `json:"published_at"`
	Incomplete  bool            `json:"incomplete"`
	Images      []CreatedImage  `json:"images"`
	Files       []CreatedFile   `json:"files"`
	Raw         json.RawMessage `json:"-"`
}

// CreatedImage is an image of a created release.
type CreatedImage struct {
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
}

// CreatedFile is a file of a created release.
type CreatedFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

// CreateRelease creates and publishes a release of product (a product uid).
func (c *VendorClient) CreateRelease(ctx context.Context, product string, rel NewRelease) (*CreatedRelease, error) {
	var out struct {
		Data json.RawMessage `json:"data"`
	}
	path := "/api/v1/vendor/products/" + url.PathEscape(product) + "/releases"
	if err := c.do(ctx, http.MethodPost, path, "", map[string]any{"release": rel}, &out); err != nil {
		return nil, err
	}
	if trimmed := bytes.TrimSpace(out.Data); len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, errors.New("Breakwater API returned an invalid release: data is not an object")
	}
	var cr CreatedRelease
	if err := json.Unmarshal(out.Data, &cr); err != nil {
		return nil, fmt.Errorf("Breakwater API returned an invalid release: %w", err)
	}
	cr.Raw = out.Data
	return &cr, nil
}
