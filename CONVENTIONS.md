# Conventions

## Repository Posture

This repository pairs **specs + code**: the `specs/` corpus is the normative protocol contract, the Rust workspace under `crates/` is the implementation, and the root-level docs (`ARCHITECTURE.md`, `docs/operators/RUNBOOK.md`, etc.) are the system-level orientation. Documentation and code MUST stay in sync — `AGENTS.md` §"Mandatory Updates After Every Change" enumerates what to touch on each kind of change.

## Language And Tone

- keep public project documentation in English
- prefer precise technical language over hype
- avoid fear-based positioning such as "quantum will break everything tomorrow"
- distinguish clearly between accepted decisions, proposed directions, and open questions

## Naming Rules

- Project name: `Viper PQ Chain` (short form: `Viper`; `PQ Chain` acceptable in technical contexts)
- Token: **none**. The reserve design behind the dormant `token_economics` feature is never described as live and never as an offer
- The node binary stays `pqcd` (renaming would be a breaking operator-facing change with no protocol benefit)
- Prometheus metric prefix `pqchain_*` is stable and not renamed (would break dashboards)
- Use NIST naming when available: `ML-KEM`, `ML-DSA`, `SLH-DSA`, and future `FN-DSA`
- Prefer `post-quantum-native` over vague labels like `quantum-ready`
- Use protocol terms consistently: `alg_id`, `key_version`, `KeySet`, `Algorithm Registry`, `validator set`

## Documentation Rules

- any material architecture choice must be recorded in [DECISIONS.md](./DECISIONS.md)
- if something is not decided, mark it as `TBD`, `working assumption`, or `proposed`
- roadmap items should be phase-based, not vanity-version based
- API docs must describe intended interfaces, not pretend implementation exists
- use exact dates in `YYYY-MM-DD` format
- prefer ASCII in repository docs unless there is a strong reason not to

## Decision Status Vocabulary

- `Accepted`: current baseline unless superseded by another ADR
- `Proposed`: strong direction, still open to change
- `Deferred`: intentionally postponed
- `Rejected`: considered and intentionally not pursued
- `Superseded`: replaced by a later ADR, named in the entry; kept for the record
- `Reserved`: designed and recorded, implemented behind a dormant feature, not active on the public chain

## Specification Status Vocabulary

Every file in `specs/` carries exactly one `**Status**:` line:

- `Draft`: being written; not a contract yet
- `Proposed`: complete, open for review
- `Accepted`: the contract; code conforms to it
- `Normative`: accepted and backed by conformance tests or vectors
- `Reserved`: designed and kept, implemented behind a dormant feature (token economics), not active
- `Historical`: report of a retired chain, kept for the audit trail

## Deployment Role Vocabulary

`single_node`, `validator`, `sentry`, `full`, `rpc`, `archive`, `bootnode` (ADR-069) — the same
word in `node.json`, the Helm chart, `pqcd ceremony`, Ansible and the documents. "Proposer" is the
consensus role of the validator elected to propose a block, not a deployment role.

## Code Direction

- Rust-first core: Rust 1.92.0 pinned via `rust-toolchain.toml`; workspace `unsafe_code = "warn"` plus `// SAFETY:` invariant comments where unsafe is unavoidable (vendored `slh-dsa`, `librocksdb-sys`, libp2p network buffers)
- Deterministic CBOR (RFC 8949) for every signed protocol object (ADR-004)
- Benchmark data and signature sizes are first-class system-design inputs, not after-the-fact tuning (see `crates/pqc-crypto/benches/sig_verify.rs` and `crates/pqc-consensus/benches/block_throughput.rs`)
- Security-critical paths (`pqc-crypto`, `pqc-state::apply`, mempool admission) stay small, explicit, and independently testable; `unwrap_used` / `expect_used` / `indexing_slicing` are workspace-level clippy denies

## Implemented Stack

This is the locked stack (ADR-053), carried unchanged through the private chains and into the public release.

| Concern | Choice | Source |
|---------|--------|--------|
| Core node language | Rust 1.92.0 (edition 2021) | `rust-toolchain.toml`, `Cargo.toml [workspace.package]` |
| PQ signatures | RustCrypto `ml-dsa` 0.1.0-rc.8 (FIPS 204) + `slh-dsa` 0.1 vendored (FIPS 205) | `Cargo.toml` |
| PQ KEM | RustCrypto `ml-kem` 0.3.0-rc.2 (FIPS 203) | `Cargo.toml` |
| Hashing | `sha3` 0.10 — SHAKE-256 XOF (FIPS 202) | `Cargo.toml` |
| Serialization | `ciborium` 0.2 — deterministic CBOR (RFC 8949) per SPEC-TX-001 §4 | `Cargo.toml` |
| Storage | RocksDB 0.22 (Apache 2.0); `multi-threaded-cf` + `lz4` | `Cargo.toml`, ADR-032 / TASK-103 |
| P2P transport | rust-libp2p with ML-KEM-768 authenticated session handshake (TASK-045, ADR-041) | `crates/pqc-p2p` |
| Logging / observability | `tracing` 0.1 + JSON subscriber; Prometheus text exposition under `/v1/metrics` | `Cargo.toml`, ADR `pqchain_*` metric namespace |
| Build environment | `flake.nix` (Nix-pinned) | `flake.nix`, `flake.lock` |
| Conformance | RustCrypto + ACVP vectors at `crates/pqc-crypto/tests/acvp_conformance.rs`; SUPERCOP / eBATS for cross-platform sanity | `tests/acvp/` |

## Change Management

- use conventional commit prefixes such as `docs:`, `feat:`, `fix:`, `refactor:`, and `chore:`
- update [CHANGELOG.md](./CHANGELOG.md) for meaningful repository-level changes
- update [TASKS.md](./TASKS.md) when a foundation item is completed or newly opened
- do not collapse working assumptions into accepted facts without recording the change in [DECISIONS.md](./DECISIONS.md)
