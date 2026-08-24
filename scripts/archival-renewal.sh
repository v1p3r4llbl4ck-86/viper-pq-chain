#!/usr/bin/env bash
# Archival ERS renewal runner — SPEC-ARCHIVAL-001 §8.3, TASK-165 / M4.6.
#
# Periodically invokes the archival sidecar's renew subcommand to submit
# RFC 4998 `ArchiveTimeStampChain` renewal transactions for every
# archival record whose oldest TSA signature is within the renewal
# horizon. Designed to be driven by cron at a 6-month cadence:
#
#   0 3 1 */6 *   root  /usr/local/bin/archival-renewal.sh
#
# Exit codes:
#   0  — success (all due records renewed or skipped cleanly)
#   1  — config missing / sidecar binary absent
#   2  — sidecar exited non-zero; retry at the next cron tick
#
# Environment:
#   VIPER_SIDECAR_BIN    — path to viper-archival-sidecar (default: /usr/local/bin/viper-archival-sidecar)
#   VIPER_SIDECAR_CONFIG — path to sidecar.toml            (default: /etc/pqchain/sidecar.toml)
#   VIPER_PASSPHRASE     — keystore passphrase             (required; read from operator vault)
#   VIPER_SINCE_EPOCH    — optional lower-bound epoch      (default: 0, walk all)
#
# The script is intentionally small — it's a cron wrapper, not the
# renewal implementation. All the protocol work lives in the sidecar's
# `renew` subcommand (see `viper_archival_sidecar::renew`).

set -euo pipefail

SIDECAR_BIN="${VIPER_SIDECAR_BIN:-/usr/local/bin/viper-archival-sidecar}"
CONFIG_PATH="${VIPER_SIDECAR_CONFIG:-/etc/pqchain/sidecar.toml}"
SINCE_EPOCH="${VIPER_SINCE_EPOCH:-0}"

if ! command -v "$SIDECAR_BIN" >/dev/null 2>&1; then
    echo "archival-renewal: sidecar binary not found at $SIDECAR_BIN" >&2
    exit 1
fi

if [[ ! -f "$CONFIG_PATH" ]]; then
    echo "archival-renewal: sidecar config missing at $CONFIG_PATH" >&2
    exit 1
fi

if [[ -z "${VIPER_PASSPHRASE:-}" ]]; then
    echo "archival-renewal: VIPER_PASSPHRASE unset — expected from operator vault" >&2
    exit 1
fi

exec "$SIDECAR_BIN" renew \
    --config "$CONFIG_PATH" \
    --since "$SINCE_EPOCH"
