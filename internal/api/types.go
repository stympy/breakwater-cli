package api

// ProductRef names a product or vendor.
type ProductRef struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// Release is one item of the release list.
type Release struct {
	Product     ProductRef `json:"product"`
	Version     string     `json:"version"`
	PublishedAt string     `json:"published_at"`
}

// Manifest is the release manifest, format 1.
type Manifest struct {
	Format            int             `json:"format"`
	Vendor            ProductRef      `json:"vendor"`
	Product           ProductRef      `json:"product"`
	Version           string          `json:"version"`
	Notes             string          `json:"notes"`
	PublishedAt       string          `json:"published_at"`
	Incomplete        bool            `json:"incomplete"`
	IncompleteReasons []string        `json:"incomplete_reasons"`
	Registry          string          `json:"registry"`
	Images            []ManifestImage `json:"images"`
	Files             []ManifestFile  `json:"files"`
}

// ManifestImage is an image (or OCI artifact) of a release. Kind is
// "internal" (on the Breakwater registry) or "external".
type ManifestImage struct {
	Kind           string `json:"kind"`
	Reference      string `json:"reference"`
	Digest         string `json:"digest"`
	MediaType      string `json:"media_type"`
	Size           int64  `json:"size"`
	RepositoryPath string `json:"repository_path"`
	Tag            string `json:"tag"`
}

// ManifestFile is a file attached to a release.
type ManifestFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	URL    string `json:"url"`
}
