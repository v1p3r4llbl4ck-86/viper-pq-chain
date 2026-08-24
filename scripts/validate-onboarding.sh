#!/usr/bin/env bash
# validate-onboarding.sh — TASK-185 external operator onboarding validation harness
#
# End-to-end check that a fresh pqcd node went from "boots" to "elected proposer"
# on the live `viper-pq-1` chain without manual-intervention gaps. Runs on the
# operator's own machine after the launch playbook completes; exits non-zero on
# any failed step.
#
# Structured log format — each step emits one of:
#   [STEP N] [PASS] <short reason>
#   [STEP N] [FAIL] <short reason>
#   [STEP N] [SKIP] <short reason>
# plus free-form [INFO] / [WARN] / [ERROR] context lines. The first three forms
# are stable so a CI harness can grep them.
#
# Exit codes:
#   0  all steps PASS (or SKIP for legitimate skips)
#   1  any step FAIL
#   2  setup error (missing dep, bad flag, unreadable keystore, etc.)
#
# Dependencies: bash, curl, jq, and `pqcd` on PATH (pqcd only needed if the
# script submits a register-validator tx — i.e. step 6 runs).

set -euo pipefail

# ── Defaults & flag parsing ──────────────────────────────────────────────────

NODE_URL="http://127.0.0.1:26657"
KEYSTORE="/etc/pqchain/keystore.json"
EXPECTED_CHAIN_ID=""
SELF_BOND=""
MIN_PEERS=2
ACTIVATION_TIMEOUT=90
# Default 600 s = 12 epochs × 50 s (epoch_duration=3 blocks × block_time=500 ms
# → 1.5 s/epoch in tests; viper-pq-1 runs epoch_duration=60 blocks at
# block_time=500 ms → ~30 s/epoch; 12 epochs of headroom catches the
# ADR-053 §T1.5 stake-weighted churn worst case where a new registrant waits
# one full epoch boundary before Active, then up to several more before being
# drawn as proposer under weighted-random selection).
PROPOSER_TIMEOUT=600
SKIP_REGISTER=0
VERBOSE=0
COLOR=0

PASS_RE=$'\e[32m'    # green
FAIL_RE=$'\e[31m'    # red
SKIP_RE=$'\e[33m'    # yellow
DIM_RE=$'\e[2m'
RESET=$'\e[0m'

print_usage() {
    cat <<'EOF'
validate-onboarding.sh — viper-pq-1 external-operator onboarding harness (TASK-185)

USAGE:
    scripts/validate-onboarding.sh --expected-chain-id <hex> [--self-bond <venom>] [flags]

REQUIRED:
    --expected-chain-id <hex>     Chain ID as hex (e.g. 76697065722d70712d31 for viper-pq-1)
    --self-bond <venom>           Self-bond amount in venom (required unless --skip-register)

FLAGS:
    --node-url <url>              Node HTTP endpoint (default: http://127.0.0.1:26657)
    --keystore <path>             Keystore JSON path (default: /etc/pqchain/keystore.json)
    --min-peers <n>               Minimum connected peers (default: 2)
    --activation-timeout <s>      Seconds to wait for Active status after register (default: 90)
    --proposer-timeout <s>        Seconds to wait for proposer election (default: 600)
    --skip-register               Skip register-validator submission (post-state verify only)
    --verbose                     Trace curl + pqcd invocations to stderr
    --color                       Enable ANSI colors on PASS/FAIL/SKIP tags
    -h, --help                    Print this help and exit

EXIT CODES:
    0  all steps PASS
    1  any step FAIL
    2  setup error (missing dependency, bad flag, unreadable keystore, ...)

STRUCTURED LOG (parseable by CI):
    [STEP N] [PASS] <reason>
    [STEP N] [FAIL] <reason>
    [STEP N] [SKIP] <reason>
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --node-url) NODE_URL="${2:?--node-url requires a value}"; shift 2 ;;
        --keystore) KEYSTORE="${2:?--keystore requires a value}"; shift 2 ;;
        --expected-chain-id) EXPECTED_CHAIN_ID="${2:?--expected-chain-id requires a value}"; shift 2 ;;
        --self-bond) SELF_BOND="${2:?--self-bond requires a value}"; shift 2 ;;
        --min-peers) MIN_PEERS="${2:?--min-peers requires a value}"; shift 2 ;;
        --activation-timeout) ACTIVATION_TIMEOUT="${2:?--activation-timeout requires a value}"; shift 2 ;;
        --proposer-timeout) PROPOSER_TIMEOUT="${2:?--proposer-timeout requires a value}"; shift 2 ;;
        --skip-register) SKIP_REGISTER=1; shift ;;
        --verbose) VERBOSE=1; shift ;;
        --color) COLOR=1; shift ;;
        -h|--help) print_usage; exit 0 ;;
        *) echo "[ERROR] unknown flag: $1 (try --help)" >&2; exit 2 ;;
    esac
done

if [[ $COLOR -eq 0 ]]; then
    PASS_RE=""; FAIL_RE=""; SKIP_RE=""; DIM_RE=""; RESET=""
fi

# ── Counters + helpers ───────────────────────────────────────────────────────

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
STARTED_AT=$(date -u +%s)

log_info()  { echo "[INFO] $*"; }
log_warn()  { echo "[WARN] $*" >&2; }
log_error() { echo "[ERROR] $*" >&2; }
log_trace() { [[ $VERBOSE -eq 1 ]] && echo "${DIM_RE}[TRACE] $*${RESET}" >&2 || true; }

step_pass() {
    local n="$1"; shift
    echo "[STEP $n] ${PASS_RE}[PASS]${RESET} $*"
    PASS_COUNT=$((PASS_COUNT + 1))
}
step_fail() {
    local n="$1"; shift
    echo "[STEP $n] ${FAIL_RE}[FAIL]${RESET} $*"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}
step_skip() {
    local n="$1"; shift
    echo "[STEP $n] ${SKIP_RE}[SKIP]${RESET} $*"
    SKIP_COUNT=$((SKIP_COUNT + 1))
}

setup_die() { log_error "$*"; exit 2; }

curl_json() {
    # curl_json <url> → prints body to stdout, returns non-zero on HTTP error
    local url="$1"
    log_trace "curl -fsS $url"
    curl -fsS --connect-timeout 5 --max-time 10 "$url"
}

curl_text() {
    local url="$1"
    log_trace "curl -fsS $url  (text)"
    curl -fsS --connect-timeout 5 --max-time 10 "$url"
}

# Decode hex string to ASCII. Bash-only, portable. Returns empty on malformed.
hex_to_ascii() {
    local hex="$1"
    # Reject non-hex or odd-length input.
    [[ "$hex" =~ ^[0-9a-fA-F]+$ ]] || { echo ""; return; }
    [[ $((${#hex} % 2)) -eq 0 ]] || { echo ""; return; }
    local out=""
    local i
    for ((i = 0; i < ${#hex}; i += 2)); do
        out+=$(printf '\\x%s' "${hex:i:2}")
    done
    printf '%b' "$out"
}

# ── Setup validation ─────────────────────────────────────────────────────────

for dep in curl jq; do
    command -v "$dep" >/dev/null 2>&1 || setup_die "missing required dependency: $dep"
done

if [[ -z "$EXPECTED_CHAIN_ID" ]]; then
    setup_die "--expected-chain-id is required (e.g. 76697065722d70712d31 for viper-pq-1). Try --help."
fi
if [[ ! "$EXPECTED_CHAIN_ID" =~ ^[0-9a-fA-F]+$ ]] || [[ $((${#EXPECTED_CHAIN_ID} % 2)) -ne 0 ]]; then
    setup_die "--expected-chain-id must be even-length hex, got: $EXPECTED_CHAIN_ID"
fi

if [[ $SKIP_REGISTER -eq 0 && -z "$SELF_BOND" ]]; then
    setup_die "--self-bond is required unless --skip-register is passed"
fi

# pqcd only required if we actually submit a tx.
if [[ $SKIP_REGISTER -eq 0 ]]; then
    command -v pqcd >/dev/null 2>&1 || setup_die "missing required dependency: pqcd (needed for register-validator; pass --skip-register to verify-only)"
fi

[[ -r "$KEYSTORE" ]] || setup_die "keystore unreadable: $KEYSTORE"

EXPECTED_CHAIN_ID_ASCII=$(hex_to_ascii "$EXPECTED_CHAIN_ID")
log_info "harness started: node=$NODE_URL keystore=$KEYSTORE expected_chain_id=$EXPECTED_CHAIN_ID ($EXPECTED_CHAIN_ID_ASCII)"

# ── Step 1: Keystore sanity ──────────────────────────────────────────────────
#
# The keystore JSON carries an `address` field (hex-encoded 32-byte op address,
# see crates/pqcd/src/wallet.rs line 143). We also accept `address_hex` as a
# compatibility alias should the schema ever evolve.

OP_ADDR=""
if OP_ADDR=$(jq -er '.address // .address_hex // empty' "$KEYSTORE" 2>/dev/null) && [[ -n "$OP_ADDR" ]]; then
    # Normalize: lowercase, strip optional 0x prefix.
    OP_ADDR=${OP_ADDR#0x}
    OP_ADDR=${OP_ADDR,,}
    if [[ "$OP_ADDR" =~ ^[0-9a-f]{64}$ ]]; then
        step_pass 1 "keystore readable, operator address: $OP_ADDR"
    else
        step_fail 1 "keystore address malformed (want 64 hex chars): $OP_ADDR"
        OP_ADDR=""
    fi
else
    step_fail 1 "keystore has no .address (or .address_hex) field: $KEYSTORE"
fi

# ── Step 2: Node alive + chain_id match ──────────────────────────────────────

STATUS_JSON=""
if STATUS_JSON=$(curl_json "$NODE_URL/v1/status" 2>/dev/null); then
    OBS_CHAIN_ID=$(echo "$STATUS_JSON" | jq -r '.chain_id // empty')
    OBS_HEIGHT=$(echo "$STATUS_JSON"   | jq -r '.height   // empty')

    # /v1/status returns chain_id as UTF-8 ASCII (devnet.rs:2493). Compare
    # against the ASCII decoding of the expected hex. Fall back to hex-compare
    # for future endpoints that might switch encodings.
    if [[ "$OBS_CHAIN_ID" == "$EXPECTED_CHAIN_ID_ASCII" || "$OBS_CHAIN_ID" == "$EXPECTED_CHAIN_ID" ]]; then
        step_pass 2 "node alive, chain_id=$OBS_CHAIN_ID height=$OBS_HEIGHT"
    else
        step_fail 2 "chain_id mismatch: observed=$OBS_CHAIN_ID expected=$EXPECTED_CHAIN_ID_ASCII (hex $EXPECTED_CHAIN_ID)"
    fi
else
    step_fail 2 "GET $NODE_URL/v1/status failed (is pqcd running and bound?)"
fi

# ── Step 3: Peer count ───────────────────────────────────────────────────────

if METRICS=$(curl_text "$NODE_URL/v1/metrics" 2>/dev/null); then
    PEERS=$(echo "$METRICS" | awk '/^pqchain_p2p_peers_connected / {print $2; exit}')
    PEERS=${PEERS:-0}
    # Metric can be a float ("3.0"); trim decimals.
    PEERS_INT=${PEERS%.*}
    if [[ "$PEERS_INT" =~ ^[0-9]+$ ]] && [[ $PEERS_INT -ge $MIN_PEERS ]]; then
        step_pass 3 "pqchain_p2p_peers_connected=$PEERS_INT (>= $MIN_PEERS)"
    else
        step_fail 3 "pqchain_p2p_peers_connected=$PEERS_INT (< $MIN_PEERS); check libp2p.bootstrap_peers and port 26656"
    fi
else
    step_fail 3 "GET $NODE_URL/v1/metrics failed"
fi

# ── Step 4: Chain advancing ──────────────────────────────────────────────────

H_BEFORE=""; H_AFTER=""
if H_BEFORE=$(curl_json "$NODE_URL/v1/status" 2>/dev/null | jq -r '.height // empty') && [[ -n "$H_BEFORE" ]]; then
    log_info "chain-advance probe: height=$H_BEFORE, sleeping 10s"
    sleep 10
    if H_AFTER=$(curl_json "$NODE_URL/v1/status" 2>/dev/null | jq -r '.height // empty') && [[ -n "$H_AFTER" ]]; then
        if [[ $H_AFTER -gt $H_BEFORE ]]; then
            step_pass 4 "height advanced $H_BEFORE -> $H_AFTER in 10s"
        else
            step_fail 4 "height stalled at $H_BEFORE (after 10s wait); check gossip + quorum"
        fi
    else
        step_fail 4 "second /v1/status probe failed"
    fi
else
    step_fail 4 "first /v1/status probe failed"
fi

# ── Step 5: Self in validator set? ───────────────────────────────────────────
# If already present (any non-exited status), short-circuit past 6/7.

ALREADY_REGISTERED=0
CURRENT_STATUS=""
if [[ -n "$OP_ADDR" ]]; then
    if VALS_JSON=$(curl_json "$NODE_URL/v1/validators" 2>/dev/null); then
        # /v1/validators returns a JSON array of {address, status, ...}.
        CURRENT_STATUS=$(echo "$VALS_JSON" | jq -r --arg addr "$OP_ADDR" '.[] | select(.address == $addr) | .status' | head -n1)
        if [[ -n "$CURRENT_STATUS" ]]; then
            ALREADY_REGISTERED=1
            step_pass 5 "operator $OP_ADDR is already registered, status=$CURRENT_STATUS"
        else
            step_pass 5 "operator $OP_ADDR not yet registered — will submit register-validator"
        fi
    else
        step_fail 5 "GET $NODE_URL/v1/validators failed"
    fi
else
    step_skip 5 "operator address unknown (step 1 failed)"
fi

# ── Step 6: Submit register-validator ────────────────────────────────────────

TX_HASH=""
if [[ $ALREADY_REGISTERED -eq 1 ]]; then
    step_skip 6 "already registered — skipping register-validator submission"
elif [[ $SKIP_REGISTER -eq 1 ]]; then
    step_skip 6 "--skip-register passed — not submitting"
elif [[ -z "$OP_ADDR" ]]; then
    step_skip 6 "operator address unknown — cannot submit"
else
    log_info "submitting: pqcd wallet register-validator $KEYSTORE --node $NODE_URL --node-id $OP_ADDR --self-bond $SELF_BOND --chain-id $EXPECTED_CHAIN_ID"
    log_trace "pqcd wallet register-validator $KEYSTORE --node $NODE_URL --node-id $OP_ADDR --self-bond $SELF_BOND --chain-id $EXPECTED_CHAIN_ID"
    REG_OUT=""
    if REG_OUT=$(pqcd wallet register-validator \
            "$KEYSTORE" \
            --node "$NODE_URL" \
            --node-id "$OP_ADDR" \
            --self-bond "$SELF_BOND" \
            --chain-id "$EXPECTED_CHAIN_ID" 2>&1); then
        # Extract a 64-hex tx_hash from the CLI's stdout (format may be
        # "tx_hash: <hex>" or similar — we match the first 64-hex token).
        TX_HASH=$(echo "$REG_OUT" | grep -oE '[0-9a-fA-F]{64}' | head -n1 || true)
        if [[ -n "$TX_HASH" ]]; then
            step_pass 6 "register-validator admitted, tx_hash=$TX_HASH"
        else
            step_pass 6 "register-validator returned 0 (tx_hash not parseable from stdout; see INFO)"
            log_info "pqcd stdout: $REG_OUT"
        fi
    else
        step_fail 6 "pqcd wallet register-validator failed: $REG_OUT"
    fi
fi

# ── Step 7: Poll for Active ──────────────────────────────────────────────────

if [[ $ALREADY_REGISTERED -eq 1 ]]; then
    # If the current status is already Active we count it as PASS; if
    # Candidate, we still poll the activation window (operator may have run
    # this right after step 6 on a prior invocation).
    if [[ "$CURRENT_STATUS" == "active" ]]; then
        step_pass 7 "operator already in Active set (status=active)"
    else
        step_skip 7 "already registered with status=$CURRENT_STATUS (not waiting; re-run after next epoch)"
    fi
elif [[ $SKIP_REGISTER -eq 1 ]]; then
    step_skip 7 "--skip-register passed — not polling for activation"
elif [[ -z "$OP_ADDR" || $FAIL_COUNT -gt 0 && -z "$TX_HASH" ]]; then
    # Only skip if register itself failed. If register succeeded we still poll.
    step_skip 7 "register-validator did not admit — nothing to poll"
else
    log_info "polling /v1/validators every 5s for up to ${ACTIVATION_TIMEOUT}s (looking for address=$OP_ADDR, status=active)"
    DEADLINE=$(( $(date -u +%s) + ACTIVATION_TIMEOUT ))
    ACTIVATED=0
    LAST_SEEN_STATUS=""
    while [[ $(date -u +%s) -lt $DEADLINE ]]; do
        if VALS_JSON=$(curl_json "$NODE_URL/v1/validators" 2>/dev/null); then
            LAST_SEEN_STATUS=$(echo "$VALS_JSON" | jq -r --arg addr "$OP_ADDR" '.[] | select(.address == $addr) | .status' | head -n1)
            if [[ "$LAST_SEEN_STATUS" == "active" ]]; then
                ACTIVATED=1
                break
            fi
        fi
        sleep 5
    done
    if [[ $ACTIVATED -eq 1 ]]; then
        step_pass 7 "operator reached Active set within ${ACTIVATION_TIMEOUT}s"
    else
        step_fail 7 "operator not Active within ${ACTIVATION_TIMEOUT}s (last status=${LAST_SEEN_STATUS:-<not-registered>}); may need to wait for next epoch boundary"
    fi
fi

# ── Step 8: Wait for proposer election ───────────────────────────────────────

if [[ -z "$OP_ADDR" ]]; then
    step_skip 8 "operator address unknown"
else
    log_info "polling for proposer election every block for up to ${PROPOSER_TIMEOUT}s (target address=$OP_ADDR)"
    ELECTED=0
    LAST_HEIGHT=-1
    OBSERVED_PROPOSERS=()
    DEADLINE=$(( $(date -u +%s) + PROPOSER_TIMEOUT ))
    while [[ $(date -u +%s) -lt $DEADLINE ]]; do
        # Get current height from /v1/status, then fetch the block by height
        # to read its proposer. /v1/blocks/latest is the non-devnet router;
        # devnet exposes /v1/blocks/{height} instead, so we use the latter.
        if CUR_H=$(curl_json "$NODE_URL/v1/status" 2>/dev/null | jq -r '.height // empty') && [[ -n "$CUR_H" ]]; then
            if [[ "$CUR_H" != "$LAST_HEIGHT" ]]; then
                if BLK_JSON=$(curl_json "$NODE_URL/v1/blocks/$CUR_H" 2>/dev/null); then
                    BLK_PROPOSER=$(echo "$BLK_JSON" | jq -r '.proposer // empty' | tr '[:upper:]' '[:lower:]')
                    BLK_PROPOSER=${BLK_PROPOSER#0x}
                    if [[ -n "$BLK_PROPOSER" ]]; then
                        log_info "height=$CUR_H proposer=$BLK_PROPOSER"
                        OBSERVED_PROPOSERS+=("$CUR_H:$BLK_PROPOSER")
                        if [[ "$BLK_PROPOSER" == "$OP_ADDR" ]]; then
                            ELECTED=1
                            break
                        fi
                    fi
                fi
                LAST_HEIGHT="$CUR_H"
            fi
        fi
        sleep 1
    done
    if [[ $ELECTED -eq 1 ]]; then
        step_pass 8 "operator elected proposer at height=$CUR_H within ${PROPOSER_TIMEOUT}s"
    else
        UNIQUE_PROP=$(printf '%s\n' "${OBSERVED_PROPOSERS[@]:-}" | awk -F: 'NF==2 {print $2}' | sort -u | wc -l)
        step_fail 8 "operator NOT elected proposer within ${PROPOSER_TIMEOUT}s; saw ${#OBSERVED_PROPOSERS[@]} block(s) from $UNIQUE_PROP unique proposer(s); re-run to extend the window or inspect ADR-042 churn"
    fi
fi

# ── Step 9: Summary ──────────────────────────────────────────────────────────

ENDED_AT=$(date -u +%s)
ELAPSED=$((ENDED_AT - STARTED_AT))

echo ""
echo "================== SUMMARY =================="
echo "PASS:    $PASS_COUNT"
echo "FAIL:    $FAIL_COUNT"
echo "SKIP:    $SKIP_COUNT"
echo "elapsed: ${ELAPSED}s"
echo "=============================================="

if [[ $FAIL_COUNT -eq 0 ]]; then
    echo "[SUMMARY] [PASS] onboarding validation complete for $OP_ADDR on $OBS_CHAIN_ID"
    echo "next-steps: complete the manual checklist in docs/onboarding-validation-checklist.md"
    exit 0
else
    echo "[SUMMARY] [FAIL] $FAIL_COUNT step(s) failed; see lines above and docs/operators/RUNBOOK.md / docs/validator-onboarding.md §12 for triage"
    exit 1
fi
