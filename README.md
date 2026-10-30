# breakwater

`breakwater` is the command-line tool for customers of software vendors who
distribute through [Breakwater](https://breakwaterapp.com). It turns a release
you're licensed for into a single verified bundle you can carry into an
air-gapped network, then loads that bundle into Docker or your own registry.

The release page in the Breakwater portal shows the exact commands for each
release, with your product and version filled in.

## Install

Download the archive for your platform from
[GitHub Releases](https://github.com/stympy/breakwater-cli/releases) and put
`breakwater` on your PATH. Each release also has a `checksums.txt`. Or, with
Go 1.26 or newer:

```bash
go install github.com/stympy/breakwater-cli/cmd/breakwater@latest
```

## Credentials

Use a customer pull token from the Breakwater portal. The CLI looks for
credentials in this order:

1. `--username <name> --password-stdin`, which reads the token from one line of stdin.
2. The environment variables `BREAKWATER_USERNAME` and `BREAKWATER_TOKEN`, used only if both are set.
3. Docker's credential store for the registry host, so a prior
   `docker login registry.breakwaterapp.com` is enough.

Defaults: API `https://app.breakwaterapp.com` (`--host`) and registry
`registry.breakwaterapp.com` (`--registry-host`).

## Commands

### `breakwater releases`

Lists the releases your token can see. `--product <slug>` narrows it to one
product; `--json` prints JSON.

### `breakwater bundle create <product> <version>`

Pulls the release's images and files and writes one bundle file, by default
`<product>-<version>.bwbundle.tar`.

```bash
breakwater bundle create api 2.4.1
breakwater bundle create api 2.4.1 --platform linux/amd64 -o api.bwbundle.tar
```

- `--platform os/arch[/variant],...`: keep only these platforms of multi-platform images. Without it, all platforms are kept. A platform that an image doesn't have is an error naming the image.
- `-o`, `--output <file>`: where to write the bundle.
- `--cli-binaries linux/amd64,windows/amd64`: also put `breakwater` binaries for these platforms in the bundle (downloaded from GitHub Releases and checked against `checksums.txt`), so the offline side can verify and load without installing anything. Available for linux, darwin and windows on amd64 and arm64.
- `--force`: overwrite the output file if it exists. If `create` fails partway, no file is left at the output path.

Breakwater records that you created a bundle. If that call fails, you get a
warning and the bundle is still made.

### `breakwater bundle verify <file>`

Checks the bundle's structure and every digest in it. It needs no network, so
run it after you carry the bundle across.

```bash
breakwater bundle verify api-2.4.1.bwbundle.tar
```

### `breakwater bundle load <file>`

Verifies the bundle, then loads it. Pick exactly one target.

```bash
# Into the local Docker
breakwater bundle load api-2.4.1.bwbundle.tar --docker

# Into your own registry
breakwater bundle load api-2.4.1.bwbundle.tar --registry registry.example.com/mirror
```

- `--docker`: load the images into the local Docker. Artifacts that aren't container images (Helm charts, Zarf packages) are skipped and listed.
- `--registry host[/prefix]`: push the images to your registry.
- `--username <name> --password-stdin`: the target registry's credentials. Without them, Docker's credential store is used, or none.
- `--insecure`: allow plain HTTP to the `--registry` host. Registries are otherwise reached only over HTTPS.
- `--rewrite-files <dir>`: write the release's compose and YAML files to `<dir>`, with their `image:` lines pointing at the loaded or pushed images.

#### Image names in your registry

- Images hosted by Breakwater: `<registry>/<repository path>:<tag>`, for example `registry.example.com/mirror/acme/api:2.4.1`.
- Images from elsewhere: `<registry>/<source host>/<path>:<tag>`, for example `registry.example.com/mirror/docker.io/library/postgres:16.4`. A port in the source host becomes `_`: `localhost:5000` is `localhost_5000`.

Images are pushed by digest first, then the tag is set, so digests match the
originals. One exception: if `--platform` removed platforms from a
multi-platform image, the filtered index has a new digest. Pull it by tag, or
use the files from `--rewrite-files`. `--docker` loads the image for your
Docker's platform only.

## The bundle

A bundle is one uncompressed tar file. Its first entry, `bundle.json`, lists
every other entry with its path, size and SHA-256.
It holds the images' blobs, the release's files, and optionally
`breakwater` binaries. The format is versioned; a newer bundle than your CLI
understands is refused with a request to upgrade.

## Where your credentials go

Your token goes only to the Breakwater API (`--host`) and the Breakwater
registry (`--registry-host`). Images hosted elsewhere are pulled anonymously.
API requests never follow redirects, and a redirect to another host (such as
blob storage) never carries your token. An image or file that claims to live
on Breakwater but points at another host is an error, not a request.

## Reading bundles safely

Treat a bundle as untrusted input. `verify` and `load` read it as a stream
and refuse, before writing or pushing anything: a truncated or altered file,
a changed byte in any layer, extra or duplicate entries, paths that escape
(`../x`), symlinks, absurd declared sizes, and a `bundle.json` that isn't
first. Text from a bundle is stripped of control characters before it's
printed, and files written with `--rewrite-files` can't leave the directory you
name.

## Development

Go 1.26 is pinned in `mise.toml`.

```bash
go test ./...        # no network or Docker needed
script/integration   # real registry:2 in Docker; builds and runs the binary
```

## Releasing

Tag a version and push the tag:

```bash
git tag v1.2.3
git push origin v1.2.3
```

GitHub Actions runs GoReleaser, which publishes the binaries and
`checksums.txt` to GitHub Releases.

## License

Apache-2.0.
