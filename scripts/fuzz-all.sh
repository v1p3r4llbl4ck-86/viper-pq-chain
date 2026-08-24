#!/usr/bin/env bash
# fuzz-all.sh — run all libFuzzer targets with a per-target budget.
#
# Requires:
#   rustup toolchain install nightly
#   cargo install cargo-fuzz
#
# Usage:
#   scripts/fuzz-all.sh              # smoke run: 10_000 iterations / target
#   scripts/fuzz-all.sh --full       # long run: -max_total_time=7200 / target (2 h / target)
#
# Exits non-zero on the first target that crashes or hits a sanitizer violation.
# Corpus dirs under fuzz/corpus/<target>/ are used as the starting corpus and
# are mutated in-place (libFuzzer adds interesting new inputs).
#
# TASK-156: Phase 8 audit target is >=24 CPU-hour per fuzz target. Invoke with
# --full on three machines in parallel, or run for eight hours nightly for three
# nights via the operator cron.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FUZZ_MANIFEST="${REPO_ROOT}/fuzz/Cargo.toml"

TARGETS=(
    # Original targets (TASK-156, TX/hash surface)
    fuzz_decode_tx
    fuzz_validate_tx
    fuzz_shake256
    # TASK-216 extensions — block decoder, P2P envelope, signed vote
    # (consensus hot-path bytes from arbitrary peers)
    fuzz_decode_block
    fuzz_p2p_envelope
    fuzz_signed_vote
)

MODE="smoke"
if [[ "${1:-}" == "--full" ]]; then
    MODE="full"
fi

if [[ "${MODE}" == "smoke" ]]; then
    LIBFUZZER_ARGS=(-runs=10000)
    echo "[fuzz-all] smoke mode — 10 000 iterations per target"
else
    # 2 h per target = 6 CPU-hour total per invocation; run four times for the
    # 24-hour acceptance threshold per target.
    LIBFUZZER_ARGS=(-max_total_time=7200)
    echo "[fuzz-all] full mode — max_total_time=7200s (2 h) per target"
fi

command -v cargo >/dev/null || { echo "cargo not in PATH" >&2; exit 1; }

for target in "${TARGETS[@]}"; do
    echo
    echo "[fuzz-all] === ${target} ==="
    corpus_dir="${REPO_ROOT}/fuzz/corpus/${target}"
    if [[ ! -d "${corpus_dir}" ]]; then
        echo "  warning: ${corpus_dir} missing — libFuzzer will start from empty corpus"
    else
        seed_count="$(find "${corpus_dir}" -maxdepth 1 -type f -name '*.bin' | wc -l | tr -d ' ')"
        echo "  seeding with ${seed_count} corpus file(s) from ${corpus_dir}"
    fi

    cargo +nightly fuzz run "${target}" \
        --manifest-path "${FUZZ_MANIFEST}" \
        -- "${LIBFUZZER_ARGS[@]}"
done

echo
echo "[fuzz-all] all targets completed without crashes."
