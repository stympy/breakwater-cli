# CLAUDE.md

`breakwater` is an open-source Go CLI for Breakwater customers: it turns a licensed release into a verified offline bundle, verifies it, and loads it into Docker or a private registry.

## Commands

Go 1.26 comes from mise; the default `go` on PATH may be older, so prefix every command with `mise exec go@1.26 --`.

```bash
mise exec go@1.26 -- go test ./...      # no network or Docker needed
mise exec go@1.26 -- go vet ./...
mise exec go@1.26 -- go build ./cmd/breakwater && ./breakwater version
mise exec go@1.26 -- script/integration   # real registry:2 in Docker (BW_TEST_REGISTRY), build tag `integration`
```

Version is set with `-ldflags "-X github.com/stympy/breakwater-cli/internal/version.Version=..."` (default `dev`).

## Package map

- `cmd/breakwater`: main, calls `cli.Execute`
- `internal/cli`: cobra commands; each subcommand file is added in `newRootCommand`; `globals` carries the persistent flags
- `internal/api`: customer API client (never follows redirects; file downloads only from the API origin)
- `internal/credentials`: credential resolution
- `internal/bundle`: bundle format: `Writer`, streaming `Scan` (the hostile-input checks), `Open`/`Validate`; `bundle/bundletest` builds test bundles from ggcr images for any package's tests
- `internal/images`: `Collector` resolves release images by digest (platform filtering with warnings for missing platforms, credentials only for internal images on `--registry-host`, anonymous 429s turned into advice) and streams their blobs; `bundle create` downloads each blob to a temp file beside the output and retries it
- `internal/load`: `bundle load`: `ToRegistry` (names: internal `<registry>/<repository_path>:<tag>`, external `<registry>/<original host, ':' as '_'>/<repo>:<tag>`; push by digest, then the top level under the tag; a filtered index gets a new digest), `ToDocker` (one docker-archive streamed into `docker load`, for Docker's platform or `--platform`, looking inside kept nested indexes; non-image artifacts skipped), `RewriteFiles` (image: lines in compose/YAML files, written through `os.Root`)
- `internal/transport`: every HTTP transport (API, registries, GitHub): ggcr's defaults with a 60s response-header timeout, plus `--ca-file` roots added to the system's
- `internal/term`: `Clean` strips control and format characters from bundle or server text before it's printed
- `internal/selfdist`: the running binary and `--cli-binaries` downloads from GitHub Releases, checked against `checksums.txt`
- `internal/version`: version and User-Agent

## Credential rules

- Order: `--username` + `--password-stdin`; env `BREAKWATER_USERNAME` + `BREAKWATER_TOKEN` (both); Docker credential store for the registry host.
- Credentials go only to the API origin and `--registry-host`. Never to external registries (pulled anonymously), never on a followed redirect. API requests don't follow redirects; a 3xx is an error.
- An `internal` image whose host isn't `--registry-host` is an error; a file URL not on the `--host` origin is an error.
- Every HTTP request sends `User-Agent: breakwater-cli/<version>`.

## Registries over plain HTTP

Registries are reached only over HTTPS. ggcr would fall back to plain HTTP for localhost, loopback, `.local` and RFC 1918 hosts; the Collector refuses that unless the host is in the hidden `--insecure-registries` flag (comma-separated hosts). Local development against a plain-HTTP registry or proxy needs it, e.g. `breakwater bundle create api 1.0.0 --host http://localhost:3000 --registry-host localhost:5000 --insecure-registries localhost:5000`. `bundle load --registry` applies the same rule to the target registry (shared `images.HTTPSOnly`), allowing plain HTTP only with `--insecure`.

## Hostile-bundle rules

Treat a bundle as hostile on the offline side. Truncation, a flipped byte, an extra or duplicate entry, `../x`, symlinks, huge declared sizes, or `bundle.json` not being first must make `verify` and `load` fail clearly, with nothing written or pushed. Files written under a user-given directory go through `os.Root`.
