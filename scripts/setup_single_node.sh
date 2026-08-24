#!/usr/bin/env bash
# setup_single_node.sh — create directories and install config for the single-node.
# Safe to run more than once (idempotent). Does NOT start the node.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${PQCHAIN_DATA_DIR:-/var/lib/pqchain/single-node}"
CONFIG_DEST="${PQCHAIN_CONFIG_DIR:-/etc/pqchain}"
CONFIG_SRC="$REPO_DIR/configs/single-node.json"

echo "=== PQ Chain — single-node setup ==="
echo "Data dir: $DATA_DIR"
echo "Config:   $CONFIG_DEST/single-node.json"
echo

# ── 1. Create data directory ──────────────────────────────────────────────────
if [[ -w "$(dirname "$DATA_DIR")" ]] || [[ -d "$DATA_DIR" ]]; then
    mkdir -p "$DATA_DIR"
else
    sudo mkdir -p "$DATA_DIR"
    SUDO_USER="${SUDO_USER:-$(id -un)}"
    sudo chown -R "$SUDO_USER" "$DATA_DIR"
fi

# ── 2. Install config ─────────────────────────────────────────────────────────
if [[ -w "$(dirname "$CONFIG_DEST")" ]] || [[ -d "$CONFIG_DEST" ]]; then
    mkdir -p "$CONFIG_DEST"
    cp "$CONFIG_SRC" "$CONFIG_DEST/single-node.json"
else
    sudo mkdir -p "$CONFIG_DEST"
    sudo cp "$CONFIG_SRC" "$CONFIG_DEST/single-node.json"
fi

# Patch data_dir in the installed config to match actual DATA_DIR
python3 - << PYEOF
import json, sys
path = "$CONFIG_DEST/single-node.json"
with open(path) as f:
    cfg = json.load(f)
cfg["data_dir"] = "$DATA_DIR"
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
print(f"data_dir patched to {cfg['data_dir']}")
PYEOF

echo
echo "=== setup_single_node.sh complete ==="
echo "Run bootstrap: pqcd bootstrap $CONFIG_DEST/single-node.json"
echo "Run status:    pqcd status    $CONFIG_DEST/single-node.json"
echo "Run API:       scripts/run_single_node_api.sh"
