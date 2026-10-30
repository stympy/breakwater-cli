# CLAUDE.md

`breakwater` is an open-source Go CLI for Breakwater customers: it turns a licensed release into a verified offline bundle, verifies it, and loads it into Docker or a private registry.

## Commands

Go 1.26 comes from mise; the default `go` on PATH may be older, so prefix every command with `mise exec go@1.26 --`.

```bash
mise exec go@1.26 -- go test ./...      # no network or Docker needed
mise exec go@1.26 -- go vet ./...
mise exec go@1.26 -- go build ./cmd/breakwater && ./breakwater version
```

Version is set with `-ldflags "-X github.com/stympy/breakwater-cli/internal/version.Version=..."` (default `dev`).

## Package map

- `cmd/breakwater`: main, calls `cli.Execute`
- `internal/cli`: cobra commands; each subcommand file is added in `newRootCommand`; `globals` carries the persistent flags
- `internal/credentials`: credential resolution
- `internal/version`: version and User-Agent

## Credential rules

- Order: `--username` + `--password-stdin`; env `BREAKWATER_USERNAME` + `BREAKWATER_TOKEN` (both); Docker credential store for the registry host.
- Credentials go only to the API origin and `--registry-host`. Never to external registries (pulled anonymously), never on a followed redirect. API requests don't follow redirects; a 3xx is an error.
- An `internal` image whose host isn't `--registry-host` is an error; a file URL not on the `--host` origin is an error.
- Every HTTP request sends `User-Agent: breakwater-cli/<version>`.

## Hostile-bundle rules

Treat a bundle as hostile on the offline side. Truncation, a flipped byte, an extra or duplicate entry, `../x`, symlinks, huge declared sizes, or `bundle.json` not being first must make `verify` and `load` fail clearly, with nothing written or pushed. Files written under a user-given directory go through `os.Root`.
