# Container images

This directory holds the Dockerfiles that produce the OCI images for the
Viper PQ Chain stack. The release workflow (`.github/workflows/release.yml`)
builds, signs, scans and pushes them to `ghcr.io` on every `vX.Y.Z` tag.

## Images produced

| Image | Source binary | Default port(s) | Healthcheck |
|---|---|---|---|
| `ghcr.io/v1p3r4llbl4ck-86/pqcd` | `crates/pqcd` | 26656 (P2P: UDP QUIC + TCP/TLS), 26657 (API) | `GET /v1/status` |
| `ghcr.io/v1p3r4llbl4ck-86/viper-archival-sidecar` | `crates/viper-archival-sidecar` | (none — TSA client) | process liveness |

Both are:

- Release image `linux/amd64` only (the release Dockerfile is `docker/pqcd-release.Dockerfile`; `docker/pqcd.Dockerfile` is the from-source build).
- Multi-stage — Rust 1.92.0 builder + debian:12-slim runtime. Final image is ~80-110 MB.
- Built with `cargo-chef` so dependency compilation is reused across CI runs (~80% cycle-time savings on green Cargo.lock).
- Non-root: each image has a dedicated system user (uid 10001 pqchain, 10003 archival).
- Signed via `cosign` keyless (Sigstore Fulcio + Rekor), GitHub Actions OIDC issuer (`token.actions.githubusercontent.com`).
- Scanned by Trivy on every build (HIGH/CRITICAL CVEs gate the pipeline).
- Shipped with a CycloneDX SBOM attached as an OCI artefact via `cosign attest`.

OCI image labels follow the `org.opencontainers.image.*` spec — `revision`,
`created`, `version` filled in by CI from the git context.

## Tag scheme

| Trigger | Tags applied |
|---|---|
| Git tag `vX.Y.Z` | `:X.Y.Z`, `:X.Y`, `:X`, `:latest` |

## Local build (manual, for testing)

```bash
# From the repo root.
docker buildx build \
    --file docker/pqcd.Dockerfile \
    --tag pqcd:local \
    --build-arg VCS_REF=$(git rev-parse --short HEAD) \
    --build-arg BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ") \
    --build-arg VERSION=$(git describe --tags --always) \
    --load \
    .
```

Replace `pqcd.Dockerfile` with the target binary's Dockerfile.

For multi-arch local builds:

```bash
docker buildx create --name viper-builder --use
docker buildx build \
    --platform linux/amd64,linux/arm64 \
    --file docker/pqcd.Dockerfile \
    --tag ghcr.io/v1p3r4llbl4ck-86/pqcd:dev \
    --push \
    .
```

(`--load` does NOT support multi-arch — must `--push` to a registry.)

## Running

For joining `viper-testnet-4` with the image see the container recipe in [docs/validator-onboarding.md](../docs/validator-onboarding.md) (pin `ghcr.io/v1p3r4llbl4ck-86/pqcd:v0.2.5`).

```bash
# pqcd — typically as a StatefulSet via the helm chart, but for a local
# smoke test:
docker run --rm \
    -e VIPER_API_PORT=26657 \
    -p 26657:26657 \
    -v $(pwd)/local-config.json:/etc/pqchain/node.json:ro \
    -v pqcd-data:/var/lib/pqchain \
    ghcr.io/v1p3r4llbl4ck-86/pqcd:latest \
    devnet-serve /etc/pqchain/node.json

# viper-archival-sidecar (mount config)
docker run --rm \
    -v $(pwd)/sidecar.toml:/etc/viper-archival-sidecar/sidecar.toml:ro \
    ghcr.io/v1p3r4llbl4ck-86/viper-archival-sidecar:latest
```

## Verifying signatures

```bash
# Cosign keyless verification (Sigstore Fulcio identity + Rekor transparency).
cosign verify \
    --certificate-identity-regexp "^https://github.com/v1p3r4llbl4ck-86/viper-pq-chain/\.github/workflows/release\.yml@" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    ghcr.io/v1p3r4llbl4ck-86/pqcd:latest

# Pull and verify the SBOM.
cosign download attestation \
    --predicate-type "https://cyclonedx.org/bom/v1.5" \
    ghcr.io/v1p3r4llbl4ck-86/pqcd:latest \
    | jq '.payload | @base64d | fromjson'
```

## Why debian:12-slim and not distroless?

Debian-slim ships a shell, `apt`, `getent`, etc., which makes runtime
debugging tractable for anyone auditing the image. The size
penalty (~80 MB vs ~30 MB distroless) is acceptable; the hardening gain
of distroless is partially defeated anyway by RocksDB's libstdc++ /
libgcc dependency. We can revisit when the chain matures and we have a
24/7 SRE rotation that doesn't need shell access into containers.
