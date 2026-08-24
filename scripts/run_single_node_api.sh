#!/usr/bin/env bash
# run_single_node_api.sh — bootstrap single-node state, then start the read API.
# Runs in foreground; Ctrl-C to stop.
set -euo pipefail

CONFIG="${1:-${PQCHAIN_CONFIG_DIR:-/etc/pqchain}/single-node.json}"
API_ADDR="${2:-0.0.0.0:26657}"
PQCD="${PQCD:-pqcd}"

echo "=== PQ Chain — single-node API ==="
echo "Config:   $CONFIG"
echo "Endpoint: http://$API_ADDR"
echo

# Verify config is readable
if [[ ! -f "$CONFIG" ]]; then
    echo "ERROR: config not found: $CONFIG"
    echo "Run scripts/setup_single_node.sh first."
    exit 1
fi

# Bootstrap once (idempotent — reads existing chain state, does nothing if empty)
echo "--- Bootstrap ---"
"$PQCD" bootstrap "$CONFIG"
echo

echo "--- Starting API server (Ctrl-C to stop) ---"
exec "$PQCD" api-serve "$CONFIG" "$API_ADDR"
