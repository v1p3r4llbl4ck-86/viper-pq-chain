# syntax=docker/dockerfile:1.7
#
# viper-archival-sidecar — out-of-consensus RFC 3161 TSA anchoring daemon
# (ADR-045, M4 archival overlay). Reads sidecar.toml from /etc/viper-archival-
# sidecar/sidecar.toml by default; no inbound HTTP listener (it's a TSA
# *client* — outbound only).

ARG RUST_VERSION=1.92
ARG DEBIAN_CODENAME=bookworm

FROM rust:${RUST_VERSION}-slim-${DEBIAN_CODENAME} AS builder
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
        clang \
        libclang-dev \
        pkg-config \
        build-essential \
        cmake \
        git \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry \
    --mount=type=cache,target=/usr/local/cargo/git,id=cargo-git \
    --mount=type=cache,target=/workspace/target,id=target-archival \
    cargo build --release --bin viper-archival-sidecar \
    && cp /workspace/target/release/viper-archival-sidecar /workspace/viper-archival-sidecar \
    && strip /workspace/viper-archival-sidecar

FROM debian:12-slim AS runtime
ARG TARGETPLATFORM

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
        ca-certificates \
        libstdc++6 \
        libgcc-s1 \
        procps \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10003 archival \
    && useradd  --system --uid 10003 --gid archival \
        --home-dir /home/archival --shell /usr/sbin/nologin --create-home archival \
    && mkdir -p /var/lib/viper-archival-sidecar /etc/viper-archival-sidecar \
    && chown -R archival:archival /var/lib/viper-archival-sidecar /etc/viper-archival-sidecar

COPY --from=builder /workspace/viper-archival-sidecar /usr/local/bin/viper-archival-sidecar

USER archival
WORKDIR /home/archival

# No exposed ports — this is a TSA client only. Liveness == process up.
HEALTHCHECK --interval=60s --timeout=3s --start-period=15s --retries=3 \
    CMD pgrep -x viper-archival-sidecar > /dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/viper-archival-sidecar"]
# Defaults to the conventional config path; override via the chart if needed.
CMD ["--config", "/etc/viper-archival-sidecar/sidecar.toml"]

ARG VCS_REF
ARG BUILD_DATE
ARG VERSION
LABEL org.opencontainers.image.title="viper-archival-sidecar" \
      org.opencontainers.image.description="Viper PQ Chain archival overlay — RFC 3161 / RFC 4998 anchoring (ADR-045)" \
      org.opencontainers.image.url="https://pqchain.agwswebconsulting.it" \
      org.opencontainers.image.source="https://github.com/v1p3r4llbl4ck-86/viper-pq-chain" \
      org.opencontainers.image.documentation="https://github.com/v1p3r4llbl4ck-86/viper-pq-chain" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Alberto Galassi" \
      org.opencontainers.image.authors="Alberto Galassi <galassi.alberto86@gmail.com>" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.version="${VERSION}"
