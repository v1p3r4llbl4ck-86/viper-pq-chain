#!/usr/bin/env bash
# check_devnet_convergence.sh — verify that validator and full nodes converge.
# Polls the /internal/p2p/status endpoint on each node for up to TIMEOUT seconds.
set -euo pipefail

TIMEOUT="${TIMEOUT:-30}"
POLL_INTERVAL=1
MIN_HEIGHT="${MIN_HEIGHT:-1}"

VALIDATOR_P2P="${VALIDATOR_P2P:-http://127.0.0.1:26656}"
FULL_NODE_A_P2P="${FULL_NODE_A_P2P:-http://127.0.0.1:26666}"
FULL_NODE_B_P2P="${FULL_NODE_B_P2P:-http://127.0.0.1:26676}"

ENDPOINTS=("$VALIDATOR_P2P" "$FULL_NODE_A_P2P" "$FULL_NODE_B_P2P")
LABELS=("producer" "follower-a" "follower-b")

echo "=== PQ Chain devnet convergence check ==="
echo "Waiting up to ${TIMEOUT}s for cluster to reach height >= ${MIN_HEIGHT}..."
echo

status() {
    local url="$1/internal/p2p/status"
    curl -sf --max-time 2 "$url" 2>/dev/null || echo "{}"
}

start=$SECONDS

while true; do
    heights=()
    tip_hashes=()
    ok=true

    for i in "${!ENDPOINTS[@]}"; do
        resp="$(status "${ENDPOINTS[$i]}")"
        h="$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('height',0))" 2>/dev/null || echo 0)"
        t="$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tip_hash','?')[:12])" 2>/dev/null || echo '?')"
        heights+=("$h")
        tip_hashes+=("$t")
        printf "  %-12s h=%-4s tip=%s\n" "${LABELS[$i]}" "$h" "$t"
    done

    # Check convergence: all heights >= MIN_HEIGHT and all tip_hashes equal
    first_h="${heights[0]}"
    first_t="${tip_hashes[0]}"
    for i in "${!heights[@]}"; do
        [[ "${heights[$i]}" -ge "$MIN_HEIGHT" ]] || ok=false
        [[ "${tip_hashes[$i]}" == "$first_t" ]] || ok=false
    done

    if $ok; then
        echo
        echo "=== CONVERGED at height=${heights[0]} tip=${tip_hashes[0]}... ==="
        exit 0
    fi

    elapsed=$((SECONDS - start))
    if [[ "$elapsed" -ge "$TIMEOUT" ]]; then
        echo
        echo "=== TIMEOUT after ${TIMEOUT}s — cluster did not converge ==="
        exit 1
    fi

    sleep "$POLL_INTERVAL"
    echo "  --- retrying (${elapsed}s elapsed) ---"
done
