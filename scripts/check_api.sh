#!/usr/bin/env bash
# check_api.sh — curl all four read-API endpoints and show results.
# Usage: check_api.sh [base_url]   default: http://localhost:26657
set -euo pipefail

BASE="${1:-http://localhost:26657}"

echo "=== PQ Chain API check — $BASE ==="
echo

pass=0; fail=0

check() {
    local label="$1"; local url="$2"; local expect_field="$3"
    echo "--- $label ---"
    local http_code
    local body
    body="$(curl -s -w '\n%{http_code}' "$url")"
    http_code="$(echo "$body" | tail -1)"
    body="$(echo "$body" | head -n -1)"
    echo "HTTP $http_code"
    echo "$body" | python3 -m json.tool 2>/dev/null || echo "$body"
    if [[ "$http_code" == "200" ]]; then
        echo "  OK"
        ((pass++)) || true
    else
        echo "  FAIL (expected 200)"
        ((fail++)) || true
    fi
    echo
}

check "GET /v1/network"        "$BASE/v1/network"        "chain_id"
check "GET /v1/blocks/latest"  "$BASE/v1/blocks/latest"  "height"

# Grab tip_hash from network to form a block lookup (404 if no blocks yet)
echo "--- GET /v1/txs/<unknown-hash> (expect 404) ---"
http_code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/txs/$(printf '%064d' 0)")"
echo "HTTP $http_code"
if [[ "$http_code" == "404" ]]; then
    echo "  OK (unknown hash correctly returns 404)"
    ((pass++)) || true
else
    echo "  FAIL"
    ((fail++)) || true
fi
echo

echo "--- GET /v1/accounts/<genesis-address> ---"
# address_hex is derived from validator-1 key in single-node.json
GENESIS_ADDR="2ce8e8b8ae95ccd2dc258e8f310af5de4c058bf544041b9460afc7e96b583f7d"
http_code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/accounts/$GENESIS_ADDR")"
body="$(curl -s "$BASE/v1/accounts/$GENESIS_ADDR")"
echo "HTTP $http_code"
echo "$body" | python3 -m json.tool 2>/dev/null || echo "$body"
if [[ "$http_code" == "200" ]]; then
    echo "  OK"
    ((pass++)) || true
elif [[ "$http_code" == "404" ]]; then
    echo "  404 — account not in state (genesis account present only if node bootstrapped from genesis)"
    ((pass++)) || true
else
    echo "  FAIL"
    ((fail++)) || true
fi
echo

echo "=== Results: $pass passed, $fail failed ==="
[[ "$fail" -eq 0 ]]
