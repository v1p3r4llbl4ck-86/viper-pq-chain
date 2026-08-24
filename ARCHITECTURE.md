# Architecture

> **Status (2026-08)**: the **as-built** description of the code that will run
> `viper-testnet-1`, the public chain created at genesis after the first public
> release. The protocol architecture is ADR-053 (BlockHeader v1, ForkDigest signing
> domains, chain-id-bound addresses, hash registry, binary Merkle state tree,
> sync-committee light client), proven on the private chains that preceded the
> release and carried forward unchanged. Forward-looking items are marked
> "Forward:" with a pointer to their ADR. The normative contract is the `specs/`
> corpus; this file is the system-level orientation. **Token-economics modules**
> (transfer, storage fund, equivocation slashing dispatch) sit behind the dormant
> `token_economics` Cargo feature and are compiled out of the public chain.

## Architectural Intent

Viper PQ Chain is a post-quantum-native L1 whose product is trust infrastructure, not Phase 1 general-purpose execution. The architecture preserves long-term cryptographic resilience while making signature size, verification cost, and storage growth explicit design inputs.

## System Goals

- remove critical dependence on classical signatures from the chain's security model
- treat crypto agility as a protocol capability, not a later migration patch
- require deterministic transaction encoding and explicit algorithm identifiers
- price bytes and signature verification in the fee model
- keep validator communication realistic under PQ signature sizes
- optimize phase 1 for vault, attestation, and policy-driven trust workflows

## Node Roles

| Role | Responsibility | Notes |
|------|----------------|-------|
| Validator | proposes and votes on blocks | operator-run validator set (proof of authority, no stake: `self_bond = 1` for every member); growth path 3 → 24 → 50 without redesign |
| Full node | verifies chain state and serves reads | does not need to participate in consensus |
| Deployment roles (ADR-069) | `validator`, `sentry`, `full`, `rpc`, `archive`, `bootnode`, `single_node` | the `devnet.role` of `node.json`; same vocabulary in the Helm chart and `pqcd ceremony`. Sentries front the validator, everything else dials the sentries; `archive` keeps the whole history; `validator`/`bootnode` do not take public transactions. See `configs/roles/` |
| Client or wallet | creates signed transactions and manages keys | must be algorithm-aware (`alg_id`, `key_version`) from day one |
| Gateway or explorer | exposes public read APIs and the chain status page | `rpc` nodes serve the read API; the explorer/status frontend ships in the Helm chart (`charts/viper-pq-chain/files/frontend`); neither takes part in consensus |

The infrastructure and deployment model for these roles — runtime (Linux process, systemd), topology, storage layout, secrets handling, and automation — is defined by the Helm chart (`charts/viper-pq-chain/README.md`) and the per-role notes in `NODES.md` (ADR-016 for the original model). The 3-host `viper-research-1` cluster was decommissioned in 2026-07; the current deployment is a single-node k3s lab pending the `viper-testnet-1` genesis. Routine ops are tracked in `RUNBOOK.txt`.

## Layered Architecture

| Layer | Responsibility | Current direction |
|------|----------------|------------------|
| Cryptography | signatures, KEM, key rotation, algorithm registry | ML-DSA-65 default for transactions and consensus (NIST L3 — ADR-046 forbids ML-DSA-44 / Level 2 for consensus keys); SLH-DSA-SHAKE-192s as the hash-based consensus fallback (ADR-043); SLH-DSA-SHA2-128s / SLH-DSA-SHAKE-128s for AA accounts and key recovery; SLH-DSA-SHAKE-256s for the M4 archival overlay only (ADR-045); FN-DSA-padded-512 registered as a non-consensus reduced-fee class; ML-KEM-768 for authenticated P2P transport. Authoritative registry: `crates/pqc-crypto/src/alg.rs` + `crates/pqc-crypto/src/registry.rs`. |
| Transaction layer | canonical encoding, replay protection, fee accounting, mempool admission | deterministic CBOR plus explicit `alg_id` and `key_version` |
| Consensus | deterministic block assembly, round-based voting, proposer rotation, finality, quorum rules, equivocation detection, validator coordination | Tendermint-like three-phase BFT (Prevote → Precommit → Commit) with proposer rotation — normatively specified in `specs/consensus.md` (SPEC-CONSENSUS-001, ADR-027); HotStuff-like linear communication remains a later optimization (ADR-007); static single-producer `producer_loop` retained for single-node development and testing only; multi-validator deployments use the `consensus_loop` (TASK-083–085) |
| Execution | applies built-in operations, meters gas via a centralized provisional schedule v0, settles actual fee and refund semantics, and commits per-tx state transitions | transfer, vault-create, `attestation_create`, the first key-management slices (`key_add`, `key_rotate`, `key_revoke`), and a minimal `governance_proposal(registry_update)` path are now implemented; broader built-ins and full governance lifecycle remain phased |
| State | stores balances, keysets, attestations, validator data, registry entries, and governance receipts | versioned state with migration hooks; attestation records, mutable registry `min_fee` / lifecycle state, and governance receipts now participate in deterministic state roots and checkpoint snapshots |
| Storage and sync | persistence, pruning, snapshots, and state sync | RocksDB-backed canonical block persistence (ADR-032 / TASK-103) plus trusted local checkpoints; state remains derivable from canonical history, checkpoints only accelerate bootstrap, and the multi-node slice reuses canonical stored blocks for follower catch-up. Operator-driven snapshot pruning is exposed via `pqcd snapshot-prune` (TASK-187a) and chain-growth visibility via the `pqchain_chain_data_bytes` metric (TASK-187); cold-storage export of pruned snapshots is exposed via `pqcd cold-storage-export` (TASK-188, S3 upload path partial); fuller state sync remains a later target |
| P2P | peer discovery, block propagation, consensus traffic, peer identity | local static-peer block propagation and catch-up implemented; ML-KEM-768 three-step authenticated session handshake implemented (TASK-045); block fetch and snapshot serve require per-request session token; peer discovery and full consensus-traffic routing remain later targets |
| Service API | business-friendly REST endpoints for domain-specific use cases | `/api/credentials/issue` and `/api/credentials/{id}` for credential issuance and verification; `/api/proofs/anchor` and `/api/proofs/{id}` for document proof anchoring; `/api/health` for node health; `/api/notarize` and `/api/verify/{id}` for notarization; `GET /docs` serves interactive Swagger UI; `GET /openapi.yaml` serves the OpenAPI 3.0 spec; all service endpoints are thin wrappers over chain primitives (attestation, proof anchor) with business-friendly field names |
| Observability | metrics, logs, tracing, and incident visibility | `GET /v1/metrics` and `GET /internal/metrics` serve Prometheus text exposition format (TASK-051); structured tracing events at block commit/import, bootstrap, and sync failure; incident-response playbook in RUNBOOK.txt §17 |

## Transaction Path

1. A client builds a deterministic CBOR payload.
2. The client signs it with an explicit `sig_alg_id` and `sig_key_version`.
3. The mempool checks size, fee sufficiency, replay protection, and verification budget.
4. In the current prototype slice, a local proposer loop reads admitted mempool entries, assembles the next candidate block, commits it against local state, appends the result to the active chain, persists the canonical block record to disk, and can recover after restart either by full replay from genesis or by loading a trusted local checkpoint and replaying only the tail blocks; invalid checkpoints must fall back to full replay. Attestation records, keyset lifecycle changes, governance receipts, and mutable algorithm-registry fields created on-chain are part of the same replay-derived state and therefore influence the deterministic `state_root` and recovered read views.
5. In the local multi-node devnet slice, followers use a static peer list to poll for the latest committed height, fetch canonical block bytes for missing heights, replay each candidate block against local state, and persist it only if parent linkage and replay-derived integrity checks succeed.
6. Validators verify signatures, fee rules, and state transitions.
7. Consensus finalizes the block.
8. Finalized state is committed to storage and exposed through read interfaces.

## Core Data Objects

### Account

- address
- balance
- nonce
- keyset entries (see KeySet below)

### KeySet Entry

Each account owns a KeySet of 1..N key entries, each with:

- `alg_id` — u16 algorithm identifier (e.g. `0x0002` = ML-DSA-65, `0x0003` = ML-DSA-87, `0x0010` = FN-DSA-padded-512, `0x0020` = SLH-DSA-SHA2-128s, `0x0021` = SLH-DSA-SHAKE-192s; full enum in `crates/pqc-crypto/src/alg.rs::AlgId`)
- `pk_bytes` — raw public key bytes
- `key_version` — monotonically increasing integer; used by the verifier to look up the correct key
- `valid_from_height` — block height from which this key is considered active
- `status` — Pending (key registered but not yet valid), Active, Revoked
- `allowed_tx_types` — policy restricting which operation types may be signed with this key (e.g. SLH-DSA keys restricted to rotation and recovery operations only)

### Transaction Envelope

- `tx_version`
- `chain_id`
- `msg_type`
- `sender`
- `nonce`
- `fee`
- `fee_tip` — optional priority tip (omitted from CBOR encoding when zero)
- `gas_limit`
- `payload`
- `sig_alg_id`
- `sig_key_version`
- `signature`

### Algorithm Registry

Each entry maps `alg_id` to:

- `spec_ref` — reference to the FIPS or specification document
- `param_set` — parameter set identifier (e.g. ML-DSA-65, ML-DSA-44)
- `allowed_use_cases` — which operation types may use this algorithm
- `min_fee` — minimum fee required when this algorithm is used (allows governance to penalize discouraged algorithms via fee)
- `lifecycle_status` — `active` | `discouraged` | `deprecated` | `banned`

## Fee Model

The baseline fee formula is:

```
fee = base_fee + byte_fee × tx_bytes + sigverify_fee[alg_id] + exec_fee
```

- `byte_fee` — prices bandwidth and storage cost of the raw transaction
- `sigverify_fee[alg_id]` — per-algorithm cost proportional to measured CPU cycles for verification; updatable via governance as benchmarks evolve
- `exec_fee` — execution gas for state transitions
- `sigverify_fee` for SLH-DSA must be significantly higher than ML-DSA because its verification rate is ~60x slower (~951 verify/s vs ~55k verify/s on reference hardware)

Fee classes per algorithm — registry baseline (`crates/pqc-crypto/src/registry.rs`) plus eBATS (Zen 4, assembly-backed) reference numbers:

| Algorithm | alg_id | Sig size | Verify/s (reference) | Fee class | Use |
|-----------|--------|----------|---------------------|-----------|-----|
| ML-DSA-44 | `0x0001` | 2,420 B | ~89,000 | V-B standard | Transactions only — ADR-046 forbids consensus |
| ML-DSA-65 | `0x0002` | 3,309 B | ~55,000 | V-B standard (reference) | Default for transactions and consensus |
| ML-DSA-87 | `0x0003` | 4,627 B | ~37,000 | V-B standard | Higher-security transactions and consensus |
| FN-DSA-padded-512 | `0x0010` | 666 B | ~62,000 | V-A reduced | Registered; not consensus-eligible (ADR-046) |
| SLH-DSA-SHA2-128s | `0x0020` | 7,856 B | ~951 | V-C premium | AA accounts, key recovery |
| SLH-DSA-SHAKE-128s | `0x0023` | 7,856 B | ~951 | V-C premium | AA accounts, key recovery |
| SLH-DSA-SHAKE-192s | `0x0021` | 16,224 B | ~312 | V-C premium | Consensus fallback (ADR-043); archival overlay |
| SLH-DSA-SHAKE-256s | `0x0022` | 29,792 B | ~132 | V-C premium | Archival overlay only (ADR-045) |
| ML-KEM-768 | `0x0100` | n/a (KEM) | n/a | n/a | P2P key agreement (FIPS 203) |

Reference platform: Ubuntu 22.04 LTS (Linux 6.8.0-107-generic VM), AMD Ryzen 7 7700, pure-Rust crates (`ml-dsa`, `slh-dsa`, `ml-kem`), release build. The 129.4 effective-TPS load test (TESTING.md §Load Test Baseline) is from this same platform. See `specs/fee-model.md §6.3` for the full measured data table.

## Consensus Strategy

Viper PQ Chain runs a BFT design with a constrained validator set so PQ commit material does not overwhelm every block. The chain is **semantic PoA** (PoS-shaped data structures with hardcoded `self_bond = 1` for all validators per the 2026-05-11 pivot, see the private planning notes) — `select_epoch_proposer` is pure RANDAO modulo and unaffected by stake; on-chain validator-staking lifecycle stays compiled under the `token_economics` feature and is reactivatable if a future genesis re-introduces a token. The first implementation is Tendermint/CometBFT-like (Prevote → Precommit → Commit), normatively specified in `specs/consensus.md` (SPEC-CONSENSUS-001, ADR-027); a HotStuff-like linear-communication evolution remains the documented later optimization path (ADR-007).

Validator set sizing — the launch posture of `viper-testnet-1` and the forward growth path (ADR-013, retained for protocol-redesign discipline):

| Topology | Validator count | Quorum (2/3+1) | ML-DSA-65 commit | SLH-DSA-SHAKE-192s commit |
|-------|----------------|----------------|-----------------|---------------|
| `viper-testnet-1` at genesis (author's validator + admitted operators) | 3 | 3 | ~10 KB | ~49 KB |
| private chains 2026-04 → 2026-08 (retired) | 3 | 3 | ~10 KB | ~49 KB |
| Forward: controlled growth | 24 | ~17 | ~56 KB | ~276 KB |
| Forward: stress ceiling | 50 | ~34 | ~110 KB | ~552 KB |

The architecture must support growth from the 3-validator launch posture through 24 → 50 without a protocol redesign. SLH-DSA-SHAKE-192s commit overhead is intentionally larger because the algorithm is the hash-based fallback, not the steady-state consensus signature.

## Storage Strategy

- prune state aggressively where safe
- keep block history auditable
- support trusted local checkpoints early and state sync once the multi-node path exists
- treat signature bytes as a first-class storage cost
- keep very large signatures away from the common transaction path

## Security-Critical Boundaries

- encoding must be canonical and deterministic
- every algorithm choice must be explicit in the signed payload
- fee rules must price verification cost and raw bytes
- key rotation must be native and auditable
- governance must be able to deprecate algorithms without resetting account space

## Out Of Scope For Now

- generic smart-contract VM
- cross-chain bridge architecture
- privacy systems beyond transport and key hygiene
- high-frequency retail payment optimization
- RWA tokenization primitives in Phase 1: issuance, transfer restrictions, redemption, corporate actions, on-chain compliance engine (asset-proof anchoring is in scope; full RWA lifecycle is not — see ADR-012)

See [DECISIONS.md](./DECISIONS.md) for the decision log behind these assumptions.
