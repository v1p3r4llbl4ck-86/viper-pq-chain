# SPDX-License-Identifier: BUSL-1.1
# Container image of a release: runtime stage only, around the pqcd binary
# that the release workflow built and signed (the build context is a directory
# holding just that binary). docker/pqcd.Dockerfile is the from-source build.
FROM debian:12-slim AS runtime
ARG TARGETPLATFORM

# Runtime deps:
#   - ca-certificates: TLS to upstream services (pqcd → archival TSA, etc.)
#   - libstdc++6:      RocksDB statically links the C++ stdlib at compile but
#                      uses libstdc++.so at runtime via the bundled C++ glue.
#   - libgcc-s1:       same as above for the unwinder.
#   - curl:            healthcheck.
#   - tini:            PID 1 reaper / signal forwarder for clean SIGTERM.
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
        ca-certificates \
        libstdc++6 \
        libgcc-s1 \
        curl \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 pqchain \
    && useradd  --system --uid 10001 --gid pqchain \
        --home-dir /home/pqchain --shell /usr/sbin/nologin --create-home pqchain \
    && mkdir -p /var/lib/pqchain /etc/pqchain \
    && chown -R pqchain:pqchain /var/lib/pqchain /etc/pqchain

# The binary is the release artefact itself (same bytes as the signed tarball),
# so the image and the tarball cannot drift apart in features or build flags.
COPY pqcd /usr/local/bin/pqcd

USER pqchain
WORKDIR /home/pqchain

# Default exposed ports — overridden via NodeConfig at runtime.
#   26656 — P2P (libp2p TCP)
#   26657 — public read API + /v1/metrics
#   26658 — libp2p QUIC (when enabled)
EXPOSE 26656 26657 26658

# Healthcheck: pqcd exposes /v1/status on the API port; if we cannot reach
# it the node is failed (block production stalled, API down, or pqcd crashed).
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
    CMD curl --fail --silent --show-error \
        --max-time 4 \
        "http://127.0.0.1:${VIPER_API_PORT:-26657}/v1/status" \
        > /dev/null || exit 1

# Default cmd: print --help. Operators set the real argv via the systemd /
# helm chart command override, e.g. `pqcd devnet-serve /etc/pqchain/node.json`.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/pqcd"]
CMD ["--help"]

# OCI metadata (filled in by buildx args at build time so they reflect the
# actual git context).
ARG VCS_REF
ARG BUILD_DATE
ARG VERSION
LABEL org.opencontainers.image.title="pqcd" \
      org.opencontainers.image.description="Viper PQ Chain node binary — post-quantum L1, FIPS 203/204/205 baseline" \
      org.opencontainers.image.url="https://github.com/v1p3r4llbl4ck-86/viper-pq-chain" \
      org.opencontainers.image.source="https://github.com/v1p3r4llbl4ck-86/viper-pq-chain" \
      org.opencontainers.image.documentation="https://github.com/v1p3r4llbl4ck-86/viper-pq-chain/blob/main/docs/operators/RUNBOOK.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Alberto Galassi" \
      org.opencontainers.image.authors="Alberto Galassi <agalassi@agwswebconsulting.it>" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.version="${VERSION}"
