# Verifying a Descles edge release

Each check answers a different question. None of them proves what the edge does with your data: that
comes from reading the code ([DATA-FLOWS.md](DATA-FLOWS.md)) and watching its traffic. They tell you
that what you run is what that code builds to.

| Check | Answers | Does not answer |
|---|---|---|
| Rebuild and compare | Is this binary exactly what this source produces? | Whether the source does what you want |
| Build provenance attestation | Was it built by this repository's release workflow, from this commit? | Whether that workflow or commit is trustworthy |
| Cosign signature on the image | Did this repository's workflow publish this exact image digest? | What the image does |
| SBOM | Which dependencies are inside? | Whether those dependencies are safe |

## Rebuild and compare (strongest)

Release binaries are built with Go's reproducible settings. Use the Go toolchain the release used
(v0.1.0: go1.27.1), and a checkout with LF line endings: web assets are embedded byte for byte, so a
CRLF checkout (Git's Windows default) builds a different binary. The repository's `.gitattributes`
enforces LF; for a clone made before it existed, use `git -c core.autocrlf=false clone ...`.

```bash
git clone https://github.com/chiatzenw-cur/descles && cd descles && git checkout vX.Y.Z
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -buildid=" -o descles-edge ./cmd/edge
sha256sum descles-edge   # compare with SHA256SUMS in the release
```

## Provenance and signatures

```bash
gh attestation verify descles-edge-vX.Y.Z-linux-amd64 --repo chiatzenw-cur/descles

# the digest is attached to each release as descles-edge-image.digest
cosign verify ghcr.io/chiatzenw-cur/descles-edge@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/chiatzenw-cur/descles/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Use **cosign v3** or later: releases are signed with cosign v3, whose signature format cosign v2
cannot find ("no signatures found"). A signature from any other repository or workflow must fail
verification.

Deploy the image **by digest** (`image@sha256:...`), not by tag. `descles edge init` warns when the
compose file uses a tag.

## Base images and build tools

The Dockerfile pins its base images by digest, and the release workflow pins every GitHub Action by
commit SHA. A tag moving upstream cannot change what gets built.
