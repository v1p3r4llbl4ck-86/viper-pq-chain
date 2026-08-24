# Testing Strategy

## Current stage (2026-08-24)

Full suite on the public-release branch:

```text
cargo test --workspace --all-features
# 935 passed, 8 ignored, 0 failed
```

Notes that matter when you run it:

- `crates/pqcd/tests/malicious_node.rs` is declared with
  `required-features = ["attack-modes"]`. Without `--all-features` (or
  `--features attack-modes`) cargo skips the whole file; the attack
  modes only inject faults when the feature is on, so running the
  scenarios without it would prove nothing.
- The multi-node integration tests in `crates/pqcd/tests/` start several
  in-process nodes over loopback with fixed deadlines. They are
  load-sensitive: on a small or busy machine run them serially
  (`cargo test -p pqcd -- --test-threads=1`). Making them deterministic
  under load is TASK-239 (`KNOWN-ISSUES.md` G-03).
- The 8 ignored tests are ignored on purpose: ACVP conformance and
  timing profiles in `pqc-crypto` (auditor evidence, `-- --ignored`),
  and two long three-node soaks in `product_workflows.rs` (gossipsub
  mesh formation; 20× determinism, 5–7 minutes).
- `crates/pqc-consensus/tests/cold_sync_replay.rs` is the always-on
  replay-equivalence gate of policy P-COMPAT-001 (ADR-052, TASK-198):
  it asserts byte-identical state roots at every height against a pin
  vector and must never be ignored.

### Quality gates

Every change must pass, in this order:

| Gate | Command |
|---|---|
| Formatting | `cargo fmt --all --check` |
| Lints | `cargo clippy --workspace --all-targets --all-features -- -D warnings` |
| Supply chain | `cargo deny check` (advisories, licences, bans, sources) |
| Licence map | `scripts/check-licenses.sh` (SPDX header and `license` field per crate match `LICENSE.md`) |
| Tests | `cargo test --workspace --all-features` |
| Fuzz (scheduled / pre-release) | `scripts/fuzz-all.sh`, or per target `cargo +nightly fuzz run <target> --manifest-path fuzz/Cargo.toml`; sanitiser run with `--sanitizer=address` |

The toolchain is pinned in `rust-toolchain.toml` (1.92.0); `rustup`
picks it up automatically.

### Test inventory by crate

Static count of `#[test]` and `#[tokio::test]` functions in the sources
(unit tests plus integration tests). The per-run figure above is the
authoritative one; it also includes doc-tests and macro-generated cases.

| Crate | Test functions | Notes |
|---|---|---|
| pqc-state | 224 | apply paths, governance, quorum policy, slashing, store, fee market, Merkle state root |
| pqcd | 230 | 169 sync + 61 async; 18 integration files (see below) |
| pqc-consensus | 124 | round state machine, commit unification pins (20× variants), epochs, cold-sync replay gate |
| pqc-types | 55 | protocol types, hashing domains, codecs |
| pqc-p2p | 51 | 43 sync + 8 async; envelopes, peer scoring, hybrid TLS group offered on both ends |
| pqc-crypto | 50 | registry, envelope, sign/verify round trips, ACVP and timing (ignored) |
| pqc-tx | 31 | canonical CBOR, validation pipeline, 6 proptest targets |
| pqc-hsm | 21 | signer trait, canary self-test, local backend |
| pqc-mempool | 14 | admission, replacement, budgets |
| viper-archival-sidecar | 12 | RFC 3161 request/response, mock TSA integration |
| pqc-light-client | 11 | sync-committee selection, compact headers, attestation codec |
| pqc-tsa | 8 | DER encoder |
| pqc-keystore | 7 | keystore format, mnemonic, address derivation |

Integration files under `crates/pqcd/tests/`: `api_test`,
`bft_consensus`, `consensus_key_rotation_producer`, `deprecation_drill`,
`fault_injection`, `key_rotation_drill`, `keystore_verify_cli`,
`load_test`, `malicious_node`, `multi_node_devnet`, `observability`,
`product_workflows`, `rate_limit`, `reqwest_pq_provider`,
`scenario_runner`, `sender_budget`, `snapshot_sync`,
`wallet_rotate_peer_id`.

### Determinism discipline

Consensus-relevant changes are checked with the 20× methodology: the
same scenario is executed twenty times and every run must produce the
same tip hash and state root. Three tests enforce it:
`bft_consensus_deterministic_with_20x_runs`,
`adr_051_distributed_mode_byte_pins_20x` (unit level, milliseconds), and
the opt-in `three_node_distributed_signing_20x_determinism`.

### Conformance and side-channel evidence

- `tests/acvp/` holds NIST ACVP vectors for ML-DSA-{44,65,87} and
  SLH-DSA-SHAKE-{128s,192s,256s}; `crates/pqc-crypto/tests/acvp_conformance.rs`
  consumes them (`cargo test -p pqc-crypto -- --ignored`).
- `crates/pqc-crypto/tests/timing_profile.rs` reports p50/p90/p99 and the
  coefficient of variation of sign/verify latencies as loose sanity
  bounds. It is evidence for an auditor, not a constant-time proof; a
  dudect-style harness is TASK-155.

## Fuzz harnesses

Two complementary layers:

| Layer | Location | How to run | When |
|---|---|---|---|
| proptest property tests | `crates/pqc-tx/src/tests/fuzz.rs` | `cargo test -p pqc-tx fuzz` | every run |
| cargo-fuzz (libFuzzer) targets | `fuzz/fuzz_targets/` | `cargo +nightly fuzz run <target> --manifest-path fuzz/Cargo.toml` | scheduled and pre-release |

**proptest targets** (6, about 20 s in debug): `decode_tx` never panics
on arbitrary bytes and fails only with `EncodingInvalid`;
encode(decode(raw)) is stable; `validate_tx` never panics on raw bytes up
to 65 KiB and always returns a typed error; every `u16` maps through
`AlgId::from_u16` without panicking.

**cargo-fuzz targets** (6): `fuzz_decode_tx`, `fuzz_validate_tx`,
`fuzz_decode_block`, `fuzz_p2p_envelope`, `fuzz_signed_vote`,
`fuzz_shake256`. Requires `rustup toolchain install nightly` and
`cargo install cargo-fuzz`. `scripts/fuzz-all.sh` runs them all with a
time budget; the AddressSanitizer variant is the CI sanitiser job.

## Historical measurements (2026-04)

These figures were measured on the prototype during Phases 3–4 and are
kept as reference data. The code paths they exercise are unchanged in
their essentials; absolute numbers depend on the machine and on the
block time in the config. They were not re-run for the public release.

### Load test

`crates/pqcd/tests/load_test.rs` (`load_test_smoke`) injects N
independent senders, each with its own ML-DSA-65 key and one signed
transaction, pre-signed outside the timer, with calibrated fee
parameters active. Run the full version with:

```text
LOAD_TX_COUNT=10000 cargo test --test load_test --release -- --nocapture
```

Development workstation, Windows 11, debug build:

| Metric | Value |
|---|---|
| Transactions injected / admitted / rejected | 100 / 100 / 0 |
| Injection TPS | 44.8 |
| Effective TPS | 38.6 |
| Mempool peak depth | 26 |
| Blocks produced | 11 |
| Duration | 2.6 s |

Linux reference VM (Ubuntu 22.04, kernel 6.8, pure-Rust `ml-dsa`),
release build, 10,000 transactions, before and after the
`KeyEntry.pk_bytes: Vec<u8> → Arc<[u8]>` optimisation (TASK-062,
TASK-066):

| Metric | Before | After | Δ |
|---|---|---|---|
| Injection TPS | 82.1 | **130.7** | +59 % |
| Effective TPS | 81.6 | **129.4** | +59 % |
| Mempool peak depth | 311 | 372 | +20 % |
| Blocks produced | 199 | 107 | −46 % |
| Duration | 122.5 s | **77.3 s** | −37 % |

Bottleneck analysis: effective TPS tracked injection TPS, so the
sequential injection loop, not block assembly, was the binding
constraint; block assembly cloned the state store under the global
mutex, and with 10,000 accounts each holding a 1,952-byte public key
that was a ~19.5 MB deep copy per block. Sharing the key bytes turned
the clone into reference-count increments. Storage: 10,000 ML-DSA-65
transactions at ~3,600 B each is ~36 MB of block data; at 100 TPS
sustained that extrapolates to ~31 GB/day.

Protocol targets (SPEC-TEST-001): §3.3 devnet ≥ 100 TPS — met (129.4);
§4.5 ≥ 200 TPS — not met; the next bottleneck is the HashMap clone in
`StateStore::clone()` (~6 ms per block at 10,000 accounts).

### Criterion benchmarks (development workstation, release build, pure-Rust `ml-dsa`)

Harnesses: `crates/pqc-crypto/benches/sig_verify.rs` and
`crates/pqc-consensus/benches/block_throughput.rs`. Relative ratios are
the useful part; they are what the fee classes are calibrated on
(`specs/fee-model.md` §6.3).

| Operation | Median | Throughput (1 core) | Notes |
|---|---|---|---|
| ML-DSA-44 verify | 163 µs | ~6,130 /s | 0.70× ML-DSA-65 |
| ML-DSA-65 verify | 233 µs | ~4,290 /s | reference class |
| ML-DSA-87 verify | 390 µs | ~2,564 /s | 1.67× ML-DSA-65 |
| ML-DSA-65 commit sign | 1.37 ms | — | dominates per-block latency |
| Empty block | 11.6 µs | — | state-machine floor |
| 1 transfer per block | 20.7 µs | — | |
| state_root, 100 accounts | 112 µs | — | O(n) in account × key count |
| state_root, 500 accounts | 555 µs | — | |

### External reference (eBATS, Zen 4 at 3.8 GHz, assembly-backed)

The numbers that motivated the fee-class design; the Criterion figures
above supersede them for calibration.

| Algorithm | Signature | Approx. verify/s | Notes |
|---|---|---|---|
| ML-DSA-44 | 2,420 B | ~89,000 | NIST L2 |
| ML-DSA-65 | 3,309 B | ~55,000 | NIST L3, default |
| FN-DSA-padded-512 | 666 B | ~62,000 | smallest; FIPS 206 pending (ADR-067) |
| SLH-DSA-128s | 7,856 B | ~951 | conservative fallback, ~60× slower |
| ML-KEM-768 decapsulation | 1,088 B (ct) | ~140,000 | P2P key agreement |

### Storage growth at 200 TPS (raw transaction data only)

| Algorithm | Tx size | Per day | Per year |
|---|---|---|---|
| FN-DSA-padded-512 | ~866 B | ~15 GB | ~5.5 TB |
| ML-DSA-65 | ~3,509 B | ~60 GB | ~21.8 TB |
| SLH-DSA-128s | ~8,056 B | ~139 GB | ~50.7 TB |

Excludes indexes, state and headers. It is why SLH-DSA is kept off the
common transaction path and reserved for consensus fallback and the
archival overlay.

### Consensus commit size (2/3+1 signatures, 100-validator example)

| Algorithm | Per-validator signature | 67-signature commit |
|---|---|---|
| FN-DSA-padded-512 | 666 B | ~44 KB |
| ML-DSA-65 | 3,309 B | ~222 KB |
| SLH-DSA-128s | 7,856 B | ~526 KB |

This is why the validator set starts small (ADR-065) and why signature
aggregation is a reserved research item (ADR-061).

## Principles

- correctness before throughput claims
- deterministic behaviour before developer convenience
- test the protocol contract, not only the local implementation
- treat abuse resistance as a first-class test area
- do not optimise for coverage percentages before the code base is
  behaviourally coherent

## Validation layers

| Layer | What is validated |
|---|---|
| Documentation consistency | no contradictions across README, architecture, API, ADRs, roadmap and tasks |
| Crypto conformance | official vectors (ACVP), algorithm policy rules, registry lifecycle |
| Encoding and parsing | canonical CBOR rules, rejection of malformed or ambiguous payloads, parser fuzzing |
| Transaction semantics | nonce handling, fee sufficiency, allowed-operation checks, registry lookups |
| Consensus behaviour | finality, quorum, proposer rotation, view change, equivocation, churn and partitions, cold-sync replay equivalence |
| Abuse resistance | oversized signatures, underpriced verification, mempool and per-sender budgets, per-IP rate limits, malicious-node modes |
| Storage and recovery | persisted restart recovery, trusted checkpoints, snapshot export/import, prune safety |
| End-to-end trust workflows | attestations, proof anchors, key rotation, algorithm deprecation drills, archival records |

## Quality gates for `viper-testnet-1`

- deterministic results across repeated runs and multiple nodes
- key rotation and recovery flows exercised on the public chain
- an algorithm discouragement drill completed by governance
- storage growth measured under the chosen block time
- snapshot, prune and cold-storage workflows validated on non-archive roles
- consensus behaviour tested under validator churn and partial partitions
- the gaps in `KNOWN-ISSUES.md` §2 closed

## What is not treated as success

- throughput claims without correctness evidence
- broad API surface without stability guarantees
- benchmark-only progress that ignores migration and recovery flows
