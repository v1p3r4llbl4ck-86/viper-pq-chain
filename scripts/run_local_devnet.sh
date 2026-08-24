#!/usr/bin/env bash
# run_local_devnet.sh — start validator + two full nodes in the background.
#
# Nodes run as background processes; logs go to /tmp/pqchain-{node}.log.
# Run scripts/stop_local_devnet.sh to stop them all.
# Run scripts/check_devnet_convergence.sh to verify convergence.
set -euo pipefail

CONFIG_DIR="${PQCHAIN_CONFIG_DIR:-/etc/pqchain}"
PQCD="${PQCD:-pqcd}"
LOG_DIR="${PQCHAIN_LOG_DIR:-/tmp}"
RUST_LOG="${RUST_LOG:-info}"

echo "=== PQ Chain — local devnet start ==="
echo "Configs: $CONFIG_DIR"
echo "Logs:    $LOG_DIR/pqchain-{producer,follower-a,follower-b}.log"
echo

for node in producer follower-a follower-b; do
    cfg="$CONFIG_DIR/$node.json"
    if [[ ! -f "$cfg" ]]; then
        echo "ERROR: config not found: $cfg"
        echo "Run scripts/setup_local_devnet.sh first."
        exit 1
    fi
done

# Stop any existing instances
if [[ -f "$LOG_DIR/pqchain-producer.pid" ]]; then
    echo "Stopping existing devnet processes..."
    bash "$(dirname "${BASH_SOURCE[0]}")/stop_local_devnet.sh" 2>/dev/null || true
    sleep 1
fi

# Start validator
echo "Starting validator..."
RUST_LOG="$RUST_LOG" "$PQCD" devnet-serve "$CONFIG_DIR/producer.json" \
    > "$LOG_DIR/pqchain-producer.log" 2>&1 &
echo $! > "$LOG_DIR/pqchain-producer.pid"
echo "  PID $(cat "$LOG_DIR/pqchain-producer.pid") — log: $LOG_DIR/pqchain-producer.log"

# Give validator a moment to bind its P2P port
sleep 1

# Start full nodes
for node in follower-a follower-b; do
    echo "Starting $node..."
    RUST_LOG="$RUST_LOG" "$PQCD" devnet-serve "$CONFIG_DIR/$node.json" \
        > "$LOG_DIR/pqchain-$node.log" 2>&1 &
    echo $! > "$LOG_DIR/pqchain-$node.pid"
    echo "  PID $(cat "$LOG_DIR/pqchain-$node.pid") — log: $LOG_DIR/pqchain-$node.log"
done

echo
echo "=== devnet started ==="
echo "P2P endpoints:"
echo "  producer:   http://127.0.0.1:26656/internal/p2p/status"
echo "  follower-a: http://127.0.0.1:26666/internal/p2p/status"
echo "  follower-b: http://127.0.0.1:26676/internal/p2p/status"
echo
echo "Wait a few seconds, then check convergence:"
echo "  scripts/check_devnet_convergence.sh"
echo "To stop: scripts/stop_local_devnet.sh"
