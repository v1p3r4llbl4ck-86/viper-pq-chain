# Cryptographic Audit Scope

**Spec ID**: AUDIT-SCOPE-001  
**Version**: 0.2  
**Status**: Draft  
**History**: v0.1 written for the Phase 4 audit-readiness gate; v0.2 revised after the `viper-pq-1` launch (2026-04-25).  
**Date**: 2026-04-25  
**Produced by**: TASK-060 (Phase 4 — Hardening and Audit Readiness)  
**Gates**: Phase 5 entry (dress rehearsal and external engagement); refreshed for the external engagement window driven by TASK-115 post-launch.

> **Revision banner (2026-04-25)**: scope was first written for the Phase 4 audit-readiness gate and revised after the `viper-pq-1` launch (ADR-053, 2026-04-25). `viper-pq-1` and its successors `viper-research-1` and `viper-lab-1` have since been retired; there is no live network at the time of the public release, and the public chain `viper-testnet-2` is created at genesis after it. The in-scope crate boundaries below stay valid; auditors should be aware that the current code is post-ADR-053 (BlockHeader v1, ForkDigest signing-domain prefix, chain-id-bound address derivation, hash registry, BIP340 double-tagged hashing, multi-dim fee market, binary Merkle state tree, unified smart-account `verifier_template_id`, sync committee scaffolding). CHANGELOG `[viper-pq-1-v0.1.0]` enumerates every commit that landed since v0.1 of this scope; each is fair game. Phase-4-era findings already closed are recorded in the relevant TASK-NNN closure notes (the Phase-4 scan report stays in the private repository history) — the auditor should re-scope around ADR-053 §T1/§T2/§T3 changes rather than re-litigate Phase-4 fixes.

---

## 1. Purpose

This document identifies every crate, module, and code path that requires external cryptographic review before PQ Chain can be considered for mainnet deployment. It also records the rationale for each inclusion and exclusion, so auditors and the internal team can agree on scope without rediscovering the boundaries.

The audit scope is not the same as the test scope. Tests confirm behavior against the spec; an audit evaluates whether the cryptographic construction is sound, the implementation is free of subtle timing or memory errors, and the protocol invariants actually hold under adversarial conditions.

---

## 2. Inclusion Criteria

A module is **in primary audit scope** if it meets any of these criteria:

1. It processes or produces private key material (sign, KEM decapsulate)
2. It verifies authenticity of external data (signature verify, commit quorum, CBOR decode of signed payloads)
3. It constructs signed preimages (domain separation, hash inputs)
4. It enforces protocol invariants whose violation would allow double-spend, equivocation, or unauthorized state mutation
5. It controls admission of external data into the consensus or state machine (mempool pipeline, P2P session auth)

A module is **in secondary audit scope** if it handles data integrity (not cryptographic authenticity) — i.e., corruption detection, replay determinism, checkpoint equivalence.

Everything else is out of scope for a cryptographic audit, though general code review may still be valuable.

---

## 3. Primary Audit Scope

### 3.1 `pqc-crypto` — all production modules

| File | Audit focus |
|------|-------------|
| `src/sign.rs` | ML-DSA-65 signing: key derivation from seed, preimage construction, output format. Used for validator commit signatures and test key generation. Review: seed handling, no seed exposure in error paths. |
| `src/verify.rs` | `PqVerifier` (production) and `MlDsaVerifier` (ML-DSA dispatch) — the core signature verification path invoked on every admitted transaction and every imported block commit. Review: correct algorithm dispatch (ML-DSA-44/65/87 + SLH-DSA-SHA2-128s), FN-DSA correctly rejected (GAP-01), no timing side-channel in the verify call, correct error propagation. |
| `src/hash.rs` | SHAKE-256/32 used for `tx_hash`, `state_root` leaf hashes, address derivation, and P2P session tokens. Review: domain separation correctness, output length enforcement, no length-extension attacks on derived values. |
| `src/kem.rs` | ML-KEM-768 key generation, encapsulation, and decapsulation for P2P session authentication. Review: seed derivation (`SHAKE-256(node_id || "-kem-d/z")`), correct use of shared secret in session token derivation, no shared secret reuse across sessions. |
| `src/alg.rs` | `AlgId` type and `from_u16` exhaustive mapping. Review: no undefined algorithm ID maps to a valid verifier path; panics are absent (confirmed by proptest TASK-046). |

**Note**: `src/registry.rs` and `src/error.rs` are supporting; they carry no standalone cryptographic risk but should be read as context for the above modules.

### 3.2 `pqc-tx` — encoding and validation pipeline

| File | Audit focus |
|------|-------------|
| `src/codec.rs` | CBOR decode/encode for the full transaction envelope. Review: canonical check (step 1–2 of SPEC-TX-001 §10); non-canonical rejection without processing further; no panic on malformed input (confirmed by proptest TASK-046); correct field ordering in encode. |
| `src/validate.rs` | 15-step admission pipeline (SPEC-TX-001 §10). Review: correct ordering of lifecycle check before signature verification (step order matters for DoS resistance — see SPEC-FEE-001 §9.5); nonce replay check; fee sufficiency; balance check; no state read before signature confirmation. |
| `src/preimage.rs` | Signed preimage construction: domain separation for transaction signing. Review: the preimage is the input to `sign()` and `verify()`; any ambiguity here breaks signature binding. Confirm domain string is unique and not reusable across preimage types. |
| `src/hash.rs` | `compute_tx_hash` — SHAKE-256 over canonical CBOR bytes. Review: hash covers the full envelope including signature field (binding); matches what `GET /v1/txs/{hash}` returns. |

### 3.3 `pqc-mempool` — admission orchestration

| File | Audit focus |
|------|-------------|
| `src/admission.rs` | Orchestrates the full admission pipeline: lifecycle pre-check → CBOR decode → signature verify → fee compute → balance check → nonce check → pool insert. Review: correct ordering; no shortcut paths that skip signature verification; error propagation does not leak internal state. |
| `src/lifecycle.rs` | Algorithm lifecycle check against the Algorithm Registry. Review: `deprecated` and `banned` algorithms are rejected before signature verification CPU is spent; no registry lookup can be bypassed by a crafted `alg_id`. |

### 3.4 `pqc-state/src/apply` — state transition enforcement

Every file in this directory is in primary scope because each apply function enforces invariants whose violation would allow unauthorized state mutation.

| File | Audit focus |
|------|-------------|
| `apply/transfer.rs` | Balance debit/credit atomicity; no double-credit; sender cannot credit themselves via fee refund overflow. |
| `apply/vault.rs` | `vault_create` invariants; `allowed_tx_types` policy enforcement. |
| `apply/attestation.rs` | `attestation_create` — correct attester binding; `attestation_revoke` — unauthorized revoker rejection (`UnauthorizedRevoker`). |
| `apply/key_mgmt.rs` | I-1 invariant (`ensure_account_invariants`): account must always have ≥1 active key; `key_rotate` atomicity (revoke old + add new must be a single state mutation); `valid_from_height` enforcement; SLH-DSA restriction to key-management operations only. |
| `apply/governance.rs` | Governance proposal execution: only `registry_update` path implemented; `min_fee` and lifecycle state update must not allow reversal of forward-only transitions (`active → discouraged → deprecated → banned`). |
| `apply/proof_anchor.rs` | `InvalidClaimType` rejection; anchor record immutability after creation. |
| `apply/consensus_rotate.rs` | Phase 3 record-only path (ADR-020); review that this path does not inadvertently affect the commit quorum membership used in `validate_block_commit_quorum`. |
| `apply/validator.rs` | Validator staking lifecycle (TASK-064): `ValidatorRegister` consensus-key-must-be-ML-DSA enforcement; duplicate consensus-key rejection; `ValidatorExit` last-active-set guard; `ValidatorUnjail` state transition; self_bond deduction and return atomicity. |

### 3.5 `pqc-state/src/store.rs` — state root and mutation contract

| Focus | Detail |
|-------|--------|
| `state_root()` | PQC-STATE-ROOT-V2 derivation: sorted leaf hashes under domain `"PQC-STATE-ROOT-V2"` via SHAKE-256. Review: sort order is deterministic and canonical; domain string is unique; no leaf hash collision possible between entity types. |
| `commit_account_mutation` / `commit_alg_entry_mutation` | Leaf hash cache update on every state mutation. Review: cache is always consistent with the entity's serialized state; no stale leaf hash can persist through a state transition. |
| Account invariant enforcement | `ensure_account_invariants` called at every apply site that modifies keys. Review: called in correct positions; no apply path bypasses it. |

### 3.6 `pqc-consensus/src/commit.rs` — BFT commit quorum validation

| Focus | Detail |
|-------|--------|
| `validate_block_commit_quorum` | Verifies each `CommitSig.signature` against `commit_preimage(height, block_hash)` using the registered validator public key. Review: uses `MlDsaVerifier` directly; correct preimage; quorum threshold (⌈2/3 × N⌉ + 1) correctly computed; equivocating signature (valid bytes, wrong message) rejected — confirmed by TASK-056 Scenario 2. |
| `commit_preimage` | Domain separation for validator commit signatures. Review: same domain separation concerns as `src/preimage.rs`; must be impossible to construct a commit preimage that collides with a transaction preimage. |

### 3.7 `pqcd/src/devnet.rs` — admission entry point and P2P session auth

| Focus | Detail |
|-------|--------|
| `try_admit` | Entry point for all transaction admission (both `/v1/txs` HTTP and internal `inject_tx`). Review: always calls `admission.rs` pipeline with `MlDsaVerifier`; per-sender budget and per-IP rate limit are checked in the correct order; no path bypasses signature verification. |
| P2P session handling (`sync_loop`, `/internal/p2p/session`, `/internal/p2p/blocks/{height}`) | KEM handshake → shared secret → session token derivation → per-request token check. Review: session token is `SHAKE-256(ss || "block-fetch" || height_be64)` — correct binding to height; shared secret is not reused across sessions; session token is checked before any block data is served. |
| `GET /internal/p2p/snapshot` | Snapshot serve endpoint. Review: requires valid session token; snapshot bytes are served without additional signing — the trust boundary is the KEM session, not the snapshot content. |

---

## 4. Secondary Audit Scope

These modules handle data integrity rather than cryptographic authenticity. They should be reviewed for correctness but at lower priority than primary scope.

| Module | Focus |
|--------|-------|
| `pqc-consensus/src/recovery.rs` | Replay determinism; checkpoint validation; tail-block integrity check. An error here could allow a corrupted chain state to be accepted after restart. |
| `pqc-consensus/src/engine.rs` | Block execution pipeline; finalization of state transitions. Review: no state is committed unless block passes quorum validation; out-of-gas semantics are correct (fee charged, state reverted). |
| `pqc-consensus/src/storage.rs` | `DiskChainStore` — append-only block persistence. Review: no block can be overwritten after commit; canonical block bytes are stored verbatim. |
| `pqcd/src/devnet.rs` (snapshot import) | `import_external_snapshot` / `bootstrap_from_external_snapshot`. Review: SHAKE-256 integrity check on imported snapshot bytes; trust boundary is documented — snapshot source is a KEM-authenticated peer, not a validator-signed artifact. |

---

## 5. Out of Scope

The following are explicitly excluded from the cryptographic audit. They may benefit from general code review, but do not require cryptographic analysis.

| Module / Area | Reason for exclusion |
|---------------|---------------------|
| `pqc-types/src/*` | Pure data type definitions; no logic or invariant enforcement |
| `pqc-consensus/src/proposer.rs` | Block assembly from admitted mempool entries; proposer selection is not security-critical (any admitted tx is already validated) |
| `pqc-consensus/src/chain.rs` | In-memory active chain store; correctness matters but no cryptographic operations |
| `pqc-consensus/src/quorum.rs` | Quorum threshold arithmetic; simple integer math, no crypto |
| `pqcd/src/api.rs` | Read-only HTTP API; no state mutation, no key material handling |
| `pqcd/src/node.rs` | Node bootstrap and config loading |
| `pqcd/src/main.rs` | CLI entrypoint |
| `pqc-consensus/src/test_support.rs` | Test helpers only; not production code |
| `benches/` | Benchmark harnesses; not production code |
| `fuzz/` | Fuzz targets; valuable for testing but not a production audit target |
| Config files (`configs/*.json`) | Operational parameters; reviewed separately as part of genesis specification (ADR-023) |
| Shell scripts (`scripts/`) | Operational automation; not cryptographic |

---

## 6. Known Pre-Audit Gaps

These are implementation gaps that should be closed or explicitly accepted before engaging an external auditor. An auditor who finds these gaps independently will list them as findings.

| Gap ID | Description | Current status | Path to closure |
|--------|-------------|----------------|-----------------|
| GAP-01 | FN-DSA signature verification not implemented; `PqVerifier` returns `NotASigningAlgorithm` for FN-DSA until FIPS 206 is finalized | SLH-DSA **resolved** in TASK-063 (`PqVerifier` + `slh_dsa_sha2_128s_*`); FN-DSA remains open | Closes when FIPS 206 is finalized and `FnDsaVerifier` is implemented and audited |
| GAP-02 | SLH-DSA per-block admission cap (TBD-FEE-10) not enforced as node policy | Deferred | Phase 4 hardening task |
| GAP-03 | No validator-signed attestation on exported snapshots; trust is KEM-session-only | Documented in TASK-050 | Requires new ADR for snapshot signing |
| GAP-04 | Consensus validator set was static (ADR-020); no height-indexed membership in commit quorum | **Resolved** in TASK-064: `CommitQuorumPolicy::from_state_store()` reads active validators from on-chain registry; genesis validators seeded from config; `ValidatorExit` removes from quorum | Full height-indexed replay correctness is Phase 5 (DiskChainStore uses genesis policy for replay; on-chain changes only affect new blocks) |
| GAP-05 | `consensus_key_rotate` was record-only; recorded rotation did not affect commit quorum membership | **Partially resolved** in TASK-064: `CommitQuorumPolicy::from_state_store()` is wired; full integration of rotation records into quorum is Phase 5 | Phase 5 |
| GAP-06 | No HSM backing for KEM seed or validator signing key; seeds held in process memory | Accepted for Phase 3; Phase 5+ target | External secret manager in Phase 5 |
| GAP-07 | Tracing events and log output not audited for key material leakage | Phase 4 security review | Manual review of all tracing call sites in primary scope |

---

## 7. Audit Deliverable Expectations

An external auditor reviewing primary scope should produce findings against at least the following questions:

1. Is the signed preimage in `pqc-tx/src/preimage.rs` uniquely bound to a single transaction? Can a transaction preimage collide with a commit preimage?
2. Is SHAKE-256 domain separation in `pqc-crypto/src/hash.rs` sufficient to prevent cross-context hash collisions?
3. Is the ML-KEM session token construction in `pqcd/src/devnet.rs` resistant to replay across sessions or heights?
4. Does `ensure_account_invariants` in `pqc-state/src/store.rs` (called via `apply/key_mgmt.rs`) correctly enforce I-1 under all execution paths, including out-of-gas reversion?
5. Is the state root (PQC-STATE-ROOT-V2) resistant to second-preimage attacks given the domain-separated leaf hash construction?
6. Does `validate_block_commit_quorum` correctly reject any signature that does not verify against the current block's hash, including equivocating signatures (valid bytes, wrong message)?
7. Is the CBOR non-canonical rejection in `pqc-tx/src/codec.rs` robust enough to prevent malleability attacks on `tx_hash` derivation?
