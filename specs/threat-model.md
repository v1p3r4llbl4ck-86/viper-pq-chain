# Threat Model

**Spec ID**: THREAT-MODEL-001  
**Version**: 0.2  
**Status**: Draft  
**History**: v0.1 2026-04-12; v0.2 banner added 2026-04-25 after the `viper-pq-1` launch (chain since retired); a v0.3 deeper revision is pending.  
**Date**: 2026-04-25  
**Produced by**: TASK-061 (Phase 4 — Hardening and Audit Readiness)  
**Based on**: WHITEPAPER.md §3 (threat surfaces), implementation as of Phase 3 exit (207 tests, ADR-021)
**Implementation roadmap**: `docs/security-testing-roadmap.md` — the testing-surface plan that operationalises this spec (cargo-fuzz extensions, ASan in CI, malicious-node runtime mode, k6 abuse, Falco runtime IDS, chaos runner). When a new attack class lands here, file the matching test/scaffolding task in that roadmap.

> **Revision banner (2026-04-25)**: this threat model predates the `viper-pq-1` launch (ADR-053; that chain and its successors are retired, the public chain `viper-testnet-1` is created at genesis after the public release) and the M4 archival overlay (ADR-045). The threat surfaces it covers remain valid, but auditors should layer in three additional surfaces that are now in code: (1) **archival overlay** — TSA dependency model, RFC 4998 ERS renewal trust assumptions, sidecar key-management (`crates/viper-archival-sidecar/`); (2) **light-client + sync committee** — sync-committee equivocation, slashing assumptions, gossip-topic abuse (SPEC-LIGHT-CLIENT-001 + ADR-053 §T3.6); (3) **multi-dim fee market** — per-dimension reserve-floor capture, contention-dimension hot-spot DoS, EIP-4844 exponential-update divergence (ADR-053 §T2.1, SPEC-FEE-002 v0.2). A v0.3 deeper revision will fold in §archival, §light-client, §fee-market subsections; until then the auditor's read-around list is captured in CHANGELOG `[viper-pq-1-v0.1.0]`.

---

## 1. Purpose

This document evaluates the Phase 3 implementation against the threat surfaces declared in WHITEPAPER.md §3. For each surface, it records the mitigation status (confirmed, partial, gap, or accepted risk), the implementation evidence, and the path to closure where a gap exists.

A threat surface marked **confirmed** has been tested in integration or verified by code review against the spec. **Partial** means the mitigation exists but is incomplete or untested. **Gap** means the threat surface is unmitigated. **Accepted risk** means the gap is known, understood, and explicitly tolerated for this phase with a rationale.

This document does not produce ADRs directly. Implementation gaps that require a protocol decision are noted with a cross-reference to the relevant pending task or future ADR.

---

## 2. Attacker Classes (from WHITEPAPER.md §3.1)

| Class | Capability | In scope for Phase 3 evaluation |
|-------|-----------|--------------------------------|
| **Classical attacker** | Key theft, replay, DoS, MITM, malformed inputs, economic abuse | Yes — fully in scope |
| **Quantum attacker (CRQC)** | Signature forgery on classical algorithms, session traffic decryption | Partially in scope — PQ algorithms used; implementation correctness is Phase 4 audit scope |

---

## 3. Threat Surface Evaluation

### 3.1 Transaction Signature Attacks

**Declared mitigations** (WHITEPAPER.md §3.3): ML-DSA default, SLH-DSA fallback, account nonce, canonical encoding.

#### 3.1.1 Replay attack

| | Detail |
|-|--------|
| Threat | Attacker resubmits a previously valid signed transaction to double-spend or repeat an operation |
| Mitigation | Account nonce enforced in `pqc-tx/src/validate.rs` step 8; mempool rejects `nonce < account.nonce` with `NONCE_CONFLICT`; committed state advances nonce on every finalized tx |
| Status | **Confirmed** — tested in engine and recovery integration tests; `chain_id` enforced at validation step 4 (TASK-024) prevents cross-chain replay |
| Residual risk | None for single-chain replay. Cross-chain replay is prevented by `chain_id` binding in the signed envelope. |

#### 3.1.2 Transaction malleability

| | Detail |
|-|--------|
| Threat | Attacker modifies non-signed fields to produce a different `tx_hash` for the same semantic content, breaking receipt lookups or double-spending |
| Mitigation | `tx_hash = SHAKE-256(canonical_cbor_bytes, 32)` over the full envelope including the signature field; non-canonical CBOR encoding rejected at step 1–2 with `ENCODING_NOT_CANONICAL` |
| Status | **Confirmed** — proptest fuzzing (TASK-046) confirmed no panic on arbitrary bytes; `prop_decode_encode_round_trip_stability` confirms encode(decode(raw)) == raw |
| Residual risk | CBOR library implementation correctness; covered in audit scope (AUDIT-SCOPE-001 §3.2, question 7) |

#### 3.1.3 Signature forgery (classical)

| | Detail |
|-|--------|
| Threat | Attacker forges a transaction signature without the sender's private key |
| Mitigation | ML-DSA-65 (FIPS 204 NIST L3) as default; `MlDsaVerifier` called on every admitted transaction via `admission.rs` |
| Status | **Confirmed** — `MlDsaVerifier` wired into all live admission paths (TASK-041); product-wedge tests run with real ML-DSA-65 keypairs |
| Residual risk | Implementation correctness of the `ml-dsa` crate (pure-Rust, FIPS 204); covered by cryptographic audit (AUDIT-SCOPE-001 §3.1) |

#### 3.1.4 Signature forgery (quantum)

| | Detail |
|-|--------|
| Threat | A CRQC breaks ML-DSA-65 and forges transaction signatures |
| Mitigation | ML-DSA is a lattice-based NIST PQC standard (FIPS 204) — believed quantum-resistant; SLH-DSA-128s available as hash-based fallback for emergency rotation flows |
| Status | **Accepted risk** — soundness of ML-DSA against a CRQC is a research and standards assumption, not an implementation claim; this is the core PQ Chain thesis |
| Residual risk | If ML-DSA is broken before the algorithm can be deprecated via governance, account keys cannot be invalidated retroactively. Mitigation: governance can emergency-ban ML-DSA-65 (SPEC-GOV-001 §7.4 action_type 0x02) and users can rotate to SLH-DSA-128s. Time window between CRQC availability and governance response is the residual risk. |

#### 3.1.5 Algorithm-downgrade attack

| | Detail |
|-|--------|
| Threat | Attacker submits a transaction using a deprecated or banned algorithm to bypass signature cost or exploit a weakened algorithm |
| Mitigation | Algorithm lifecycle check at mempool admission step (before signature verification CPU is spent); `deprecated` and `banned` algorithms rejected with `UNSUPPORTED_ALGORITHM` before any crypto work |
| Status | **Confirmed** — full 4-step deprecation drill (Active→Discouraged→Deprecated→Banned) passed (TASK-055); tx admission blocked at each stage as expected |
| Residual risk | None — the lifecycle check runs before signature verification and cannot be bypassed without modifying the node |

#### 3.1.6 Multi-algorithm verifier gap

| | Detail |
|-|--------|
| Threat | A user rotates to FN-DSA or SLH-DSA (key_rotate state lifecycle succeeds) but the node cannot verify signatures from the new key, effectively locking the account |
| Current state | **Gap** — `MlDsaVerifier` only; FN-DSA and SLH-DSA signing verification not implemented (deferred from TASK-058) |
| Impact | A user who successfully executes `key_rotate` to FN-DSA or SLH-DSA will have the new key registered as Active in state, but any tx signed with the new key will be rejected at admission with `INVALID_SIGNATURE` (the verifier cannot handle the algorithm) |
| Path to closure | TASK-063 (multi-algorithm verifier backend) |
| Accepted for | Phase 3 prototype only; not acceptable for mainnet |

---

### 3.2 Consensus Attacks

**Declared mitigations** (WHITEPAPER.md §3.3): PQ signatures on all vote and commit material.

#### 3.2.1 Equivocation (single Byzantine validator)

| | Detail |
|-|--------|
| Threat | A validator signs two different blocks at the same height, causing full nodes to accept conflicting chain states |
| Mitigation | `validate_block_commit_quorum` in `pqc-consensus/src/commit.rs` verifies each `CommitSig.signature` against `commit_preimage(height, block_hash)` using the validator's registered public key; a valid signature over a different block hash fails this check |
| Status | **Confirmed** — TASK-056 Scenario 2 demonstrated: a valid ML-DSA-65 signature over a phantom block's hash is correctly rejected with `INVALID_COMMIT_SIGNATURE`; the full node did not advance height |
| Residual risk | Implementation correctness of `commit_preimage` domain separation; covered in audit scope (AUDIT-SCOPE-001 question 1) |

#### 3.2.2 Byzantine majority liveness failure

| | Detail |
|-|--------|
| Threat | More than ⌊(N-1)/3⌋ validators are Byzantine; the network should halt (not produce wrong blocks) |
| Current state | **Gap** — not testable in Phase 3; static producer loop with no mechanism to simulate Byzantine quorum |
| Evidence | Documented in `specs/fault-injection-report.md` gap 1 |
| Path to closure | TASK-065 (Byzantine majority fault injection); requires multi-proposer consensus (ADR-007 HotStuff track) |

#### 3.2.3 Fork choice under split-brain

| | Detail |
|-|--------|
| Threat | Two honest chains of equal height form due to a network partition; the node must apply a deterministic fork-choice rule and not accept both |
| Current state | **Gap** — single producer; no competing tip hashes possible in current architecture; full-node sync has no fork-choice path |
| Evidence | Documented in `specs/fault-injection-report.md` gap 2 |
| Path to closure | TASK-065 + ADR-007 HotStuff track (TASK-064) |

#### 3.2.4 Long-range attack

| | Detail |
|-|--------|
| Threat | Attacker with old validator keys rewrites chain history from a past height |
| Current state | **Partial** — trusted local checkpoints exist (TASK-020); bootstrap prefers checkpoint over full replay; checkpoint integrity is verified by SHAKE-256 on load |
| Gap | No social or governance consensus on checkpoint hashes; a node that bootstraps from a snapshot trusts the snapshot source (KEM-authenticated peer, not validator-signed) |
| Path to closure | Validator-signed snapshot attestation (GAP-03 in AUDIT-SCOPE-001); governance-ratified checkpoint hashes for the mainnet bootstrap set |

#### 3.2.5 Dynamic validator set membership bypass

| | Detail |
|-|--------|
| Threat | A validator removed from the set continues to produce valid-looking commit signatures |
| Current state | **Gap** — validator set is static and loaded from config (ADR-020); `validate_block_commit_quorum` uses the genesis-configured validator set at all heights |
| Evidence | ADR-020 documents this explicitly; `consensus_key_rotate` is record-only |
| Path to closure | TASK-064 (on-chain validator staking lifecycle); commit quorum must resolve signer membership at the block's height |

---

### 3.3 P2P Transport Attacks

**Declared mitigations** (WHITEPAPER.md §3.3): ML-KEM-768 for key agreement.

#### 3.3.1 Man-in-the-middle on block fetch

| | Detail |
|-|--------|
| Threat | Attacker intercepts block data between peers and substitutes a different block |
| Mitigation | ML-KEM-768 three-step session handshake before any block data is served (TASK-045); per-request token `SHAKE-256(ss || "block-fetch" || height_be64)` authenticated per fetch |
| Status | **Confirmed** — `p2p_session_required_for_block_fetch` integration test: 401 on unauthenticated fetch, 200 after KEM handshake |
| Residual risk | Block bytes are authenticated (token-gated) but not encrypted beyond the session token. A passive observer who does not complete the KEM handshake cannot fetch blocks; a peer who does complete the handshake can read block content. For a public chain this is expected. |

#### 3.3.2 Harvest-now-decrypt-later on P2P traffic

| | Detail |
|-|--------|
| Threat | Attacker records P2P traffic today; a CRQC decrypts or forges session tokens later |
| Mitigation | ML-KEM-768 (FIPS 203 NIST L3) for session key agreement — believed quantum-resistant; session shared secret is ephemeral per `GET /internal/p2p/session` call |
| Status | **Accepted risk** — soundness of ML-KEM against CRQC is a research assumption. Session tokens derived from the shared secret inherit this assumption. |
| Residual risk | If ML-KEM is broken: attacker can replay old session tokens (mitigated by height-binding in token derivation) or forge new sessions (requires breaking the KEM for a future session). Block content is not encrypted, so eavesdropping of content is not a risk beyond session auth. |

#### 3.3.3 Eclipse / Sybil attack on peer list

| | Detail |
|-|--------|
| Threat | Attacker fills a node's peer list with malicious nodes, isolating it from honest peers |
| Current state | **Accepted risk for Phase 3** — static peer list in config; no peer discovery; no Sybil protection beyond operator-controlled peer configuration |
| Impact | A misconfigured or compromised peer list could prevent a node from receiving honest blocks; the node would not produce incorrect state (each received block is validated) but would stall |
| Path to closure | Peer discovery with reputation scoring is a Phase 4/5 infrastructure item; not on the current task list |

#### 3.3.4 DoS on P2P endpoints

| | Detail |
|-|--------|
| Threat | Attacker floods `/internal/p2p/session` with KEM handshake requests to exhaust resources |
| Current state | **Gap** — no rate limiting on P2P endpoints; per-IP rate limit (TASK-052) applies only to `/v1/txs` |
| Impact | The KEM encapsulation + decapsulation cost (~140k decap/s on reference hardware) bounds the attack throughput, but a sustained flood could increase block fetch latency |
| Path to closure | Phase 4 hardening item; rate limiting on P2P session endpoint |

---

### 3.4 Serialization and Encoding Attacks

**Declared mitigations** (WHITEPAPER.md §3.3): deterministic CBOR, reject non-canonical inputs.

#### 3.4.1 Non-canonical encoding

| | Detail |
|-|--------|
| Threat | Attacker submits a transaction with non-canonical CBOR encoding that decodes identically to a valid transaction but produces a different `tx_hash`, breaking lookup or enabling double-spend |
| Mitigation | CBOR canonical check is step 1 of the 15-step validation pipeline; non-canonical rejected with `ENCODING_NOT_CANONICAL` before any further processing |
| Status | **Confirmed** — `prop_decode_encode_round_trip_stability` proptest confirms round-trip stability; `prop_decode_tx_error_is_encoding_invalid_or_ok` confirms only `EncodingInvalid` on failure |

#### 3.4.2 Parser panic on malformed input

| | Detail |
|-|--------|
| Threat | Crafted malformed bytes cause a panic in the CBOR parser, crashing the node |
| Mitigation | `prop_decode_tx_never_panics`: 2048 cases of arbitrary bytes through `decode_tx`; no panic observed; libFuzzer target `fuzz_decode_tx` for extended sessions |
| Status | **Confirmed** — TASK-046 proptest and libFuzzer harnesses in place |
| Residual risk | Proptest covers the space probabilistically; libFuzzer coverage depends on fuzz session duration. Audit should review parser boundary conditions manually. |

---

### 3.5 Economic DoS Attacks

**Declared mitigations** (WHITEPAPER.md §3.3): fee per byte + fee per verify, mempool admission budget.

#### 3.5.1 Signature verification CPU exhaustion

| | Detail |
|-|--------|
| Threat | Attacker submits many transactions using expensive-to-verify algorithms (especially V-C / SLH-DSA) to exhaust verification CPU |
| Mitigation | V-C class fee (810,000 fee units, ~57.8× V-B) makes SLH-DSA spam expensive; per-sender admission budget (TASK-053) caps cumulative verify spend per sender per window |
| Status | **Partial** — V-C fee class calibrated and enforced; per-sender budget implemented (TASK-053). SLH-DSA per-block cap (TBD-FEE-10) not yet implemented as node policy. |
| Gap | A burst of SLH-DSA transactions from multiple senders (each within their individual budget) could still saturate verification capacity per block |
| Path to closure | Implement V-C per-block cap as node configuration parameter (SPEC-FEE-001 §10.2) |

#### 3.5.2 Bandwidth flooding with large transactions

| | Detail |
|-|--------|
| Threat | Attacker submits many maximum-size (1 MiB) transactions to exhaust bandwidth and storage |
| Mitigation | Payload size cap of 1 MiB (TASK-044); byte fee linear with tx size makes large payloads expensive; per-IP rate limit (TASK-052) |
| Status | **Confirmed** — 1 MiB cap enforced in `validate_tx` step 0 before any crypto; byte fee calibrated (`byte_fee = 2`, `sigverify_fee_v_b = 14000` — large txs pay significant byte fee) |

#### 3.5.3 Fee undercutting via discouraged algorithms

| | Detail |
|-|--------|
| Threat | Attacker bypasses the governance-raised `min_fee` penalty on discouraged algorithms by paying only the baseline class fee |
| Mitigation | `effective_sigverify_fee = max(benchmark_class_fee, registry.min_fee)` — governance-raised min_fee always dominates (SPEC-FEE-001 §5.1) |
| Status | **Confirmed** — governance proposal that raises min_fee for ML-DSA-44 (discouraged step in TASK-055) correctly applied; subsequent transactions required the raised min_fee |

#### 3.5.4 Mempool resource exhaustion

| | Detail |
|-|--------|
| Threat | Attacker fills the mempool with low-value transactions to crowd out legitimate transactions |
| Mitigation | Fee sufficiency gate; per-sender admission budget (TASK-053); replacement policy requires 10% fee bump (SPEC-FEE-001 §11); dynamic mempool pressure floor (TBD-FEE-12, not yet implemented) |
| Status | **Partial** — static admission controls in place; dynamic pressure floor is a future node policy item |

---

### 3.6 Key Material and Secret Handling

#### 3.6.1 Private key exposure in logs or traces

| | Detail |
|-|--------|
| Threat | A signing seed or private key appears in a structured tracing event, log line, or error message, and is exfiltrated by an attacker with log access |
| Current state | **Review required** — by design, private keys and seeds are not stored in node state; only public keys appear in `Account.keyset`. However, no systematic audit of all tracing call sites has been performed. |
| Evidence needed | Manual review of all `tracing::info!`, `tracing::debug!`, `tracing::error!`, `warn!`, and `debug!("{:?}", ...)` call sites in `pqc-crypto`, `pqc-state::apply`, and `pqcd::devnet` |
| Path to closure | Phase 4 security review per AGENTS.md; document findings before engaging external auditor |

#### 3.6.2 KEM seed in process memory

| | Detail |
|-|--------|
| Threat | Attacker with memory access (dump, side-channel, container escape) reads the ML-KEM seed stored in `LiveNodeState.kem_sk` |
| Current state | **Accepted risk for Phase 3** — software key storage is standard; KEM seed is held in process memory as a byte array |
| Impact | If exposed: attacker can derive the node's ML-KEM key pair and impersonate the node in future P2P sessions (not retroactively, because past shared secrets were ephemeral) |
| Path to closure | HSM-backed key storage is a Phase 5 target (GAP-06 in AUDIT-SCOPE-001) |

---

### 3.7 Checkpoint and Snapshot Integrity

#### 3.7.1 Snapshot substitution

| | Detail |
|-|--------|
| Threat | Attacker serves a crafted snapshot to a cold-starting full node; the node bootstraps from wrong state |
| Mitigation | `import_external_snapshot` verifies SHAKE-256 integrity of snapshot bytes on import; snapshot is KEM-session-authenticated (only a peer that completed the handshake can serve a snapshot) |
| Status | **Partial** — import integrity check confirmed by TASK-050 corruption-rejection tests. However, the snapshot is not signed by validators — a compromised peer that completes the KEM handshake can serve an internally consistent but historically incorrect snapshot. |
| Gap | No validator-signed attestation on exported snapshots (GAP-03 in AUDIT-SCOPE-001) |
| Path to closure | Requires a new ADR for snapshot signing; governance-ratified checkpoint hashes at mainnet genesis |

#### 3.7.2 Checkpoint / full-replay equivalence

| | Detail |
|-|--------|
| Threat | Checkpoint bootstrap produces different state than full replay from genesis, allowing a state divergence between nodes |
| Mitigation | `snapshot bootstrap + tail replay == genesis replay` invariant verified in TASK-050 integration tests (replay-equivalence test) |
| Status | **Confirmed** — 6 snapshot-sync integration tests pass including replay-equivalence; stale `tip_hash` and `state_root` mismatch detected |

---

## 4. Summary Table

| Surface | Threat | Status | Gap ID |
|---------|--------|--------|--------|
| Transaction signatures | Replay | Confirmed | — |
| Transaction signatures | Malleability | Confirmed | — |
| Transaction signatures | Forgery (classical) | Confirmed | — |
| Transaction signatures | Forgery (quantum) | Accepted risk | — |
| Transaction signatures | Algorithm downgrade | Confirmed | — |
| Transaction signatures | Multi-algorithm verifier | **Gap** | GAP-01 (TASK-063) |
| Consensus | Equivocation (single Byzantine) | Confirmed | — |
| Consensus | Byzantine majority liveness | **Gap** | TASK-065 |
| Consensus | Fork choice under split-brain | **Gap** | TASK-065 |
| Consensus | Long-range attack | Partial | GAP-03 |
| Consensus | Dynamic validator set bypass | **Gap** | GAP-04/05 (TASK-064) |
| P2P transport | MITM on block fetch | Confirmed | — |
| P2P transport | Harvest-now-decrypt-later | Accepted risk | — |
| P2P transport | Eclipse / Sybil | Accepted risk (Phase 3) | Phase 4/5 |
| P2P transport | DoS on P2P session endpoint | **Gap** | Phase 4 hardening |
| Serialization | Non-canonical encoding | Confirmed | — |
| Serialization | Parser panic | Confirmed | — |
| Economic DoS | V-C CPU exhaustion burst | Partial | TBD-FEE-10 |
| Economic DoS | Bandwidth flooding | Confirmed | — |
| Economic DoS | Fee undercutting (discouraged) | Confirmed | — |
| Economic DoS | Mempool exhaustion | Partial | TBD-FEE-12 |
| Key material | Private key in logs | **Review required** | GAP-07 |
| Key material | KEM seed in memory | Accepted risk (Phase 3) | GAP-06 |
| Snapshot integrity | Snapshot substitution | Partial | GAP-03 |
| Snapshot integrity | Checkpoint / replay equivalence | Confirmed | — |

---

## 5. Accepted Risks Register

These risks are known, understood, and explicitly accepted for Phase 3. They must be revisited before mainnet (Phase 6).

| Risk | Rationale for acceptance | Revisit trigger |
|------|--------------------------|-----------------|
| ML-DSA quantum soundness | This is the core PQ Chain thesis; if ML-DSA is broken, the protocol is compromised by design assumption, not implementation error. Emergency governance (SPEC-GOV-001 §7.4) provides a response path. | NIST or academic announcement of ML-DSA break |
| ML-KEM quantum soundness | Same rationale as ML-DSA; FIPS 203 is a finalized NIST standard | Same trigger |
| Static peer list (Sybil) | Phase 3 is a controlled devnet; operators configure peers manually | Peer discovery implementation required before public testnet |
| KEM seed in process memory | Standard software key storage; HSM backing is a Phase 5 target | Phase 5 validator onboarding design |

---

## 6. Phase 4 Closure Checklist

The following must be resolved or explicitly accepted before Phase 5 (dress rehearsal):

- [ ] GAP-01: multi-algorithm verifier (TASK-063)
- [ ] GAP-04/05: on-chain validator staking lifecycle (TASK-064); dynamic set membership in commit quorum
- [ ] GAP-07: manual review of all tracing call sites for key material leakage; findings documented
- [ ] Byzantine majority fault injection (TASK-065); liveness behavior documented
- [ ] Fork-choice behavior under split-brain: documented and either implemented or accepted with rationale
- [ ] SLH-DSA per-block admission cap (TBD-FEE-10): implemented or formally deferred with rationale
- [ ] P2P session endpoint rate limiting: implemented or formally deferred
- [ ] Cryptographic audit engagement confirmed (external auditor, scope = AUDIT-SCOPE-001)
