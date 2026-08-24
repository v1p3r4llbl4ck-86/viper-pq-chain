#!/usr/bin/env bash
# setup_local_devnet.sh — create directories and install configs for local 3-node devnet.
# Safe to run more than once (idempotent). Does NOT start any node.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_DATA="${PQCHAIN_BASE_DATA:-/var/lib/pqchain}"
CONFIG_DEST="${PQCHAIN_CONFIG_DIR:-/etc/pqchain}"

echo "=== PQ Chain — local devnet setup ==="
echo "Data base: $BASE_DATA"
echo "Configs:   $CONFIG_DEST"
echo

NODES=(producer follower-a follower-b)

# ── 1. Create data directories ────────────────────────────────────────────────
for node in "${NODES[@]}"; do
    dir="$BASE_DATA/$node"
    if [[ -w "$(dirname "$dir")" ]] || [[ -d "$dir" ]]; then
        mkdir -p "$dir"
    else
        sudo mkdir -p "$dir"
        SUDO_USER="${SUDO_USER:-$(id -un)}"
        sudo chown -R "$SUDO_USER" "$dir"
    fi
    echo "  data dir: $dir"
done

# ── 2. Install configs ────────────────────────────────────────────────────────
if [[ -w "$(dirname "$CONFIG_DEST")" ]] || [[ -d "$CONFIG_DEST" ]]; then
    mkdir -p "$CONFIG_DEST"
    COPY_CMD="cp"
else
    sudo mkdir -p "$CONFIG_DEST"
    COPY_CMD="sudo cp"
fi

for node in "${NODES[@]}"; do
    $COPY_CMD "$REPO_DIR/configs/$node.json" "$CONFIG_DEST/$node.json"
    echo "  config:   $CONFIG_DEST/$node.json"
done

# Patch data_dir in installed configs
python3 - << PYEOF
import json, os

base = "$BASE_DATA"
config_dest = "$CONFIG_DEST"

for node in ("producer", "follower-a", "follower-b"):
    path = os.path.join(config_dest, f"{node}.json")
    with open(path) as f:
        cfg = json.load(f)
    cfg["data_dir"] = os.path.join(base, node)
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2)
    print(f"  patched {path}: data_dir={cfg['data_dir']}")
PYEOF

echo
echo "=== setup_local_devnet.sh complete ==="
echo "Run devnet:    scripts/run_local_devnet.sh"
echo "Check status:  scripts/check_devnet_convergence.sh"
