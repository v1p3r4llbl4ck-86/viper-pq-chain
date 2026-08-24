#!/usr/bin/env bash
# stop_local_devnet.sh — stop validator and full node processes started by run_local_devnet.sh.
set -euo pipefail

LOG_DIR="${PQCHAIN_LOG_DIR:-/tmp}"

echo "=== PQ Chain — stopping local devnet ==="

for node in producer follower-a follower-b; do
    pidfile="$LOG_DIR/pqchain-$node.pid"
    if [[ -f "$pidfile" ]]; then
        pid="$(cat "$pidfile")"
        if kill -0 "$pid" 2>/dev/null; then
            echo "  Stopping $node (PID $pid)..."
            kill -TERM "$pid" 2>/dev/null || true
        else
            echo "  $node (PID $pid) already stopped."
        fi
        rm -f "$pidfile"
    else
        echo "  No PID file for $node."
    fi
done

echo "Done."
