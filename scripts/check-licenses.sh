#!/usr/bin/env bash
# Licence map guard (ADR-070). Fails when a crate's Cargo.toml, a Rust source's
# SPDX header, or the LICENSES/ directory drifts from LICENSE.md.
set -euo pipefail
cd "$(dirname "$0")/.."

PP="pqc-crypto pqc-types pqc-tx pqc-tsa pqc-light-client pqc-keystore"
PB="pqc-consensus pqc-state pqc-mempool pqc-p2p pqc-hsm pqcd viper-archival-sidecar"
fail=0
say() { echo "check-licenses: $*" >&2; fail=1; }

for f in Apache-2.0 BUSL-1.1 CC-BY-4.0 MIT LicenseRef-Proprietary; do
  [ -s "LICENSES/$f.txt" ] || say "missing LICENSES/$f.txt"
done
[ -s LICENSE.md ] || say "missing LICENSE.md"
[ -s NOTICE ] || say "missing NOTICE"
[ -s REUSE.toml ] || say "missing REUSE.toml"
grep -q '^Licensor:  *Alberto Galassi' LICENSES/BUSL-1.1.txt || say "BUSL-1.1 parameters block missing"
for d in vendor/libp2p-tls-pq vendor/libp2p-quic-pq; do [ -s "$d/LICENSE" ] || say "missing $d/LICENSE"; done
[ -s vendor/slh-dsa/LICENSE-MIT ] && [ -s vendor/slh-dsa/LICENSE-APACHE ] || say "missing vendor/slh-dsa licences"

expected_for() {
  case "$1" in
    crates/*) c=${1#crates/}; c=${c%%/*}
      for x in $PP; do [ "$c" = "$x" ] && { echo Apache-2.0; return; }; done
      for x in $PB; do [ "$c" = "$x" ] && { echo BUSL-1.1; return; }; done
      echo UNKNOWN ;;
    notary/*) echo LicenseRef-Proprietary ;;
    fuzz/*) echo BUSL-1.1 ;;
    *) echo SKIP ;;
  esac
}

# Cargo.toml licence field per crate
for c in $PP; do
  grep -qE '^license(\.workspace = true|\s*=\s*"Apache-2.0")' "crates/$c/Cargo.toml" || say "crates/$c: expected Apache-2.0"
done
for c in $PB; do
  grep -qE '^license\s*=\s*"BUSL-1.1"' "crates/$c/Cargo.toml" || say "crates/$c: expected BUSL-1.1"
done
[ -f notary/backend/Cargo.toml ] && { grep -qE '^license\s*=\s*"LicenseRef-Proprietary"' notary/backend/Cargo.toml || say "notary/backend: expected LicenseRef-Proprietary"; }
grep -qE '^license\s*=\s*"BUSL-1.1"' fuzz/Cargo.toml || say "fuzz: expected BUSL-1.1"
grep -qE '^license\s*=\s*"Apache-2.0"' Cargo.toml || say "workspace default must stay Apache-2.0"

# SPDX header on every Rust source outside vendor/
while IFS= read -r f; do
  exp=$(expected_for "$f")
  [ "$exp" = SKIP ] && continue
  [ "$exp" = UNKNOWN ] && { say "$f: crate not in the licence map"; continue; }
  first=$(head -n1 "$f")
  [ "$first" = "// SPDX-License-Identifier: $exp" ] || say "$f: expected '// SPDX-License-Identifier: $exp', got '$first'"
done < <(git ls-files 'crates/*.rs' 'notary/*.rs' 'fuzz/*.rs' 2>/dev/null || find crates notary fuzz -name '*.rs' 2>/dev/null)

if [ "$fail" -ne 0 ]; then echo "check-licenses: FAILED" >&2; exit 1; fi
echo "check-licenses: ok"
