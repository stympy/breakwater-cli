package load

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stympy/breakwater-cli/internal/api"
	"github.com/stympy/breakwater-cli/internal/bundle"
	"github.com/stympy/breakwater-cli/internal/term"
)

// maxRewriteSize caps a file read into memory to rewrite.
const maxRewriteSize = 16 << 20

var (
	imageLine     = regexp.MustCompile(`^(\s*(?:-\s*)?image:\s*)(["']?)([^"'\s#]+)(["']?)(.*)$`)
	digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	composeNames  = []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}
)

type rewriteFile struct {
	name    string
	content []byte
}

// planRewrite reads the bundle's files that RewriteFiles applies to: the
// compose files by name, and any other .yml or .yaml file with an image:
// line.
func planRewrite(b *bundle.Bundle) ([]rewriteFile, error) {
	var out []rewriteFile
	for _, f := range b.Header().Files {
		compose := slices.Contains(composeNames, f.Name)
		ext := strings.ToLower(filepath.Ext(f.Name))
		if !compose && ext != ".yml" && ext != ".yaml" {
			continue
		}
		if !api.ValidFileName(f.Name) {
			return nil, fmt.Errorf("file %q has an unsafe name", term.Clean(f.Name))
		}
		if f.Size > maxRewriteSize {
			return nil, fmt.Errorf("file %s is %d bytes, too large to rewrite (the limit is %d MiB)", f.Name, f.Size, maxRewriteSize>>20)
		}
		rc, err := b.File(f.Name)
		if err != nil {
			return nil, err
		}
		content, err := io.ReadAll(io.LimitReader(rc, maxRewriteSize+1))
		cerr := rc.Close()
		if err == nil {
			err = cerr
		}
		if err != nil {
			return nil, fmt.Errorf("file %s: %w", f.Name, err)
		}
		if int64(len(content)) > maxRewriteSize {
			return nil, fmt.Errorf("file %s is too large to rewrite", f.Name)
		}
		if compose || hasImageLine(string(content)) {
			out = append(out, rewriteFile{f.Name, content})
		}
	}
	return out, nil
}

func hasImageLine(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		if imageLine.MatchString(strings.TrimSuffix(line, "\r")) {
			return true
		}
	}
	return false
}

// CheckRewrite fails if any file RewriteFiles would write already exists in
// dir, so a load can refuse before it pushes or loads anything.
func CheckRewrite(b *bundle.Bundle, dir string) error {
	files, err := planRewrite(b)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	return checkAbsent(root, dir, files)
}

func checkAbsent(root *os.Root, dir string, files []rewriteFile) error {
	for _, f := range files {
		_, err := root.Lstat(f.name)
		if err == nil {
			return fmt.Errorf("%s already exists; not overwriting it", filepath.Join(dir, f.name))
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// RewriteFiles writes the bundle's compose files, and other YAML files with
// image: lines, to dir (created 0755 if missing), with each image: value
// that names a bundle image replaced by its mapped name. keepDigests is
// for --registry: a value pinned by digest gets the image's new digest.
// Without it (--docker), the digest is dropped, since docker load doesn't
// record repository digests. Quotes and the rest of the line are kept, and
// unmapped values are left alone. Existing files are never overwritten.
// It returns the paths written.
func RewriteFiles(b *bundle.Bundle, dir string, mappings []Mapping, keepDigests bool) ([]string, error) {
	files, err := planRewrite(b)
	if err != nil || len(files) == 0 {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err := checkAbsent(root, dir, files); err != nil {
		return nil, err
	}

	l := newLookup(mappings)
	var written, names []string
	// On a failure, remove what this run wrote, so a retry finds no
	// conflicts.
	fail := func(err error) ([]string, error) {
		for _, n := range names {
			_ = root.Remove(n)
		}
		return nil, err
	}
	for _, f := range files {
		path := filepath.Join(dir, f.name)
		if testHookBeforeOpen != nil {
			testHookBeforeOpen(root, f.name)
		}
		fh, err := root.OpenFile(f.name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if errors.Is(err, fs.ErrExist) {
			return fail(fmt.Errorf("%s already exists; not overwriting it", path))
		}
		if err != nil {
			return fail(err)
		}
		_, err = fh.Write([]byte(l.rewrite(string(f.content), keepDigests)))
		if cerr := fh.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = root.Remove(f.name)
			return fail(fmt.Errorf("writing %s: %w", path, err))
		}
		names = append(names, f.name)
		written = append(written, path)
	}
	return written, nil
}

// testHookBeforeOpen, if set, runs before each file is created (tests).
var testHookBeforeOpen func(root *os.Root, name string)

type lookup struct {
	byName   map[string]Mapping   // Docker-normalized From
	byDigest map[string][]Mapping // FromDigest
}

func newLookup(mappings []Mapping) *lookup {
	l := &lookup{byName: map[string]Mapping{}, byDigest: map[string][]Mapping{}}
	for _, m := range mappings {
		if n, err := DockerName(m.From); err == nil {
			if _, dup := l.byName[n]; !dup {
				l.byName[n] = m
			}
		}
		l.byDigest[m.FromDigest] = append(l.byDigest[m.FromDigest], m)
	}
	return l
}

func (l *lookup) rewrite(s string, keepDigests bool) string {
	var sb strings.Builder
	for _, piece := range strings.SplitAfter(s, "\n") {
		body, nl := strings.CutSuffix(piece, "\n")
		body, cr := strings.CutSuffix(body, "\r")
		sb.WriteString(l.rewriteLine(body, keepDigests))
		if cr {
			sb.WriteString("\r")
		}
		if nl {
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

// rewriteLine rewrites one line's image: value, if it names a mapped image.
func (l *lookup) rewriteLine(line string, keepDigests bool) string {
	m := imageLine.FindStringSubmatch(line)
	if m == nil {
		return line
	}
	prefix, q1, value, q2, rest := m[1], m[2], m[3], m[4], m[5]
	base, digest, pinned := strings.Cut(value, "@")
	var (
		mp Mapping
		ok bool
	)
	if pinned {
		if !digestPattern.MatchString(digest) {
			return line
		}
		mp, ok = l.pinned(base, digest)
	} else if n, err := DockerName(base); err == nil {
		mp, ok = l.byName[n]
	}
	if !ok {
		return line
	}
	to := mp.To
	if pinned && keepDigests {
		to += "@" + mp.ToDigest
	}
	return prefix + q1 + to + q2 + rest
}

// pinned finds the mapping for a value pinned to digest, preferring one in
// the value's repository when several images share the digest.
func (l *lookup) pinned(base, digest string) (Mapping, bool) {
	cands := l.byDigest[digest]
	if len(cands) == 0 {
		return Mapping{}, false
	}
	if repo, ok := repository(base); ok {
		for _, c := range cands {
			if r, ok := repository(c.From); ok && r == repo {
				return c, true
			}
		}
	}
	return cands[0], true
}

// repository is a reference's Docker-normalized repository, without a tag.
func repository(ref string) (string, bool) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "", false
	}
	n, err := DockerName(r.Context().Name())
	if err != nil {
		return "", false
	}
	return strings.TrimSuffix(n, ":latest"), true
}
